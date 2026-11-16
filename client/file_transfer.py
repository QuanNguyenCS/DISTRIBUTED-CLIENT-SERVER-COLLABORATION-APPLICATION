"""
Module: client.file_transfer
Mô tả: Quản lý quá trình truyền và nhận file tin cậy qua TCP:
  - Chia nhỏ file (Chunking) thành các khối 32 KB để tối ưu hóa bộ nhớ RAM.
  - Tính toán mã băm SHA-256 để xác thực tính toàn vẹn 100% bit-by-bit.
  - Ghép các mảnh file (Assembly) và lưu vào thư mục tải về.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import threading
import time
import uuid
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, Generator, Optional, Tuple

from common.logger import get_logger

logger = get_logger("client.file")

# Kích thước chuẩn mỗi chunk: 32 KB (32768 bytes)
DEFAULT_CHUNK_SIZE: int = 32 * 1024
# Giới hạn kích thước file P2P tối đa mặc định (2 GB)
MAX_TRANSFER_FILE_SIZE: int = 2 * 1024 * 1024 * 1024
# Khóa bảo vệ khi chọn tên file duy nhất để tránh ghi đè file tốt đang tồn tại
_SAVE_PATH_LOCK = threading.Lock()


def resolve_unique_save_path(save_path: str) -> str:
    """
    Trả về đường dẫn đích không ghi đè file tốt đang có sẵn trong thư mục tải về.
    Ví dụ nếu 'report.pdf' đã tồn tại -> 'report (1).pdf'.
    """
    if not os.path.exists(save_path):
        return save_path

    parent = os.path.dirname(save_path)
    base = os.path.basename(save_path)
    stem, ext = os.path.splitext(base)
    counter = 1
    while True:
        candidate = os.path.join(parent, f"{stem} ({counter}){ext}")
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def calculate_file_hash(file_path: str | Path, cancel_event=None) -> str:
    """
    Tính mã băm SHA-256 của một file trên đĩa cứng bằng cách đọc tuần tự theo khối.
    Tối ưu bộ nhớ RAM ngay cả với file dung lượng hàng trăm MB.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(64 * 1024):
            if cancel_event is not None and cancel_event.is_set():
                raise ValueError("Người dùng đã hủy quá trình truyền file.")
            sha256.update(chunk)
    return sha256.hexdigest()


def read_file_chunks(
    file_path: str | Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Generator[Tuple[int, bytes], None, None]:
    """
    Generator đọc file từng khối một cách tuần tự (Chunking).
    Trả về bộ (chunk_index, chunk_data_bytes).
    """
    with open(file_path, "rb") as f:
        index = 0
        while chunk := f.read(chunk_size):
            yield index, chunk
            index += 1


def pack_chunk_payload(
    file_id: str,
    chunk_index: int,
    total_chunks: int,
    chunk_data: bytes,
    encrypted: bool = False,
) -> bytes:
    """
    Đóng gói mảnh dữ liệu file thành payload nhị phân:
    [4 bytes độ dài metadata JSON] + [metadata JSON bytes] + [dữ liệu file thô / mã hóa]
    """
    meta = {
        "file_id": file_id,
        "chunk_index": chunk_index,
        "total_chunks": total_chunks,
        "chunk_size": len(chunk_data),
    }
    if encrypted:
        meta["encrypted"] = True
    meta_bytes = json.dumps(meta).encode("utf-8")
    prefix = struct.pack("!I", len(meta_bytes))
    return prefix + meta_bytes + chunk_data


def unpack_chunk_payload(payload: bytes) -> Tuple[Dict[str, any], bytes]:
    """
    Giải mã payload nhị phân thành metadata và dữ liệu file thô.
    """
    if len(payload) < 4:
        raise ValueError("Payload FILE_CHUNK quá ngắn để đọc độ dài header.")

    meta_len = struct.unpack("!I", payload[:4])[0]
    if len(payload) < 4 + meta_len:
        raise ValueError("Payload FILE_CHUNK bị thiếu dữ liệu metadata.")

    meta_bytes = payload[4 : 4 + meta_len]
    meta = json.loads(meta_bytes.decode("utf-8"))
    chunk_data = payload[4 + meta_len :]
    return meta, chunk_data


@dataclass
class IncomingFileTransfer:
    """
    Theo dõi tiến trình nhận một file từ người gửi theo kiểu streaming thẳng xuống file tạm .part
    để tiêu thụ RAM cố định O(1) và xác thực nghiêm ngặt index/size/SHA-256.
    """

    file_id: str
    sender: str
    file_name: str
    file_size: int
    total_chunks: int
    expected_sha256: str
    save_path: str
    received_chunks_count: int = 0
    received_bytes: int = 0
    start_time: float = field(default_factory=time.time)
    _temp_part_path: str = field(init=False)
    _part_handle: Optional[BinaryIO] = field(default=None, init=False, repr=False)
    _hasher: Any = field(default_factory=hashlib.sha256, init=False, repr=False)
    _completed: bool = field(default=False, init=False)
    _cancelled: bool = field(default=False, init=False)
    _io_lock: Any = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.file_size) is not int
            or self.file_size < 0
            or self.file_size > MAX_TRANSFER_FILE_SIZE
        ):
            raise ValueError(f"Kích thước file không hợp lệ: {self.file_size}")
        if type(self.total_chunks) is not int or self.total_chunks != max(
            1, (self.file_size + DEFAULT_CHUNK_SIZE - 1) // DEFAULT_CHUNK_SIZE
        ):
            raise ValueError(f"Số lượng chunk không hợp lệ: {self.total_chunks}")
        if self.file_size == 0 and self.total_chunks != 1:
            raise ValueError("File 0-byte chỉ được phép có 1 chunk.")
        if self.file_size > 0 and self.total_chunks > self.file_size:
            raise ValueError("total_chunks vượt quá tổng số byte của file.")
        if (
            not isinstance(self.expected_sha256, str)
            or len(self.expected_sha256.strip()) != 64
        ):
            raise ValueError("Mã băm SHA-256 kỳ vọng không hợp lệ.")
        try:
            int(self.expected_sha256.strip(), 16)
        except ValueError as exc:
            raise ValueError("Mã băm SHA-256 không đúng định dạng hex.") from exc

        self.expected_sha256 = self.expected_sha256.strip()
        self._temp_part_path = ""

    @property
    def progress_percentage(self) -> float:
        """Phần trăm hoàn thành từ 0.0 đến 100.0."""
        if self.total_chunks == 0:
            return 100.0
        return (self.received_chunks_count / self.total_chunks) * 100.0

    def _close_handle(self) -> None:
        if self._part_handle is not None:
            try:
                self._part_handle.close()
            except OSError:
                pass
            finally:
                self._part_handle = None

    def cleanup(self) -> None:
        """Đóng file handle tạm và xóa file .part còn sót lại nếu transfer chưa hoàn tất."""
        with self._io_lock:
            self._cancelled = True
            self._close_handle()
            if not self._completed:
                try:
                    if os.path.exists(self._temp_part_path):
                        os.remove(self._temp_part_path)
                except OSError:
                    pass

    def add_chunk(self, chunk_index: int, chunk_data: bytes) -> bool:
        """Kiểm tra biên chunk_index/size và ghi streaming chunk trực tiếp xuống đĩa (.part)."""
        with self._io_lock:
            if self._cancelled or self._completed:
                raise ValueError("Transfer already closed.")
            if chunk_index < 0 or chunk_index >= self.total_chunks:
                raise ValueError(
                    f"chunk_index={chunk_index} nằm ngoài phạm vi [0, {self.total_chunks})."
                )
            if chunk_index != self.received_chunks_count:
                raise ValueError(
                    f"Chunk đến sai thứ tự hoặc bị trùng lặp: kỳ vọng {self.received_chunks_count}, nhận {chunk_index}."
                )
            expected_size = min(
                DEFAULT_CHUNK_SIZE, self.file_size - self.received_bytes
            )
            if len(chunk_data) != expected_size:
                raise ValueError(
                    "Chunk length does not match the advertised file size."
                )
            if self.received_bytes + len(chunk_data) > self.file_size:
                raise ValueError(
                    f"Tổng dung lượng chunk nhận ({self.received_bytes + len(chunk_data)}) vượt quá file_size ({self.file_size})."
                )

            if self._part_handle is None:
                os.makedirs(
                    os.path.dirname(os.path.abspath(self.save_path)), exist_ok=True
                )
                fd, self._temp_part_path = tempfile.mkstemp(
                    prefix=".collab-",
                    suffix=".part",
                    dir=os.path.dirname(os.path.abspath(self.save_path)),
                )
                self._part_handle = os.fdopen(fd, "wb")

            self._part_handle.write(chunk_data)
            self._hasher.update(chunk_data)
            self.received_chunks_count += 1
            self.received_bytes += len(chunk_data)
            return self.received_chunks_count == self.total_chunks

    def assemble_and_verify(self) -> Tuple[bool, str]:
        """
        Đóng file tạm .part, kiểm tra đủ chunk/size/SHA-256 và đổi tên an toàn (không ghi đè file tốt).
        """
        with self._io_lock:
            self._close_handle()
            if self.received_chunks_count != self.total_chunks:
                self.cleanup()
                return (
                    False,
                    f"Chưa nhận đủ chunk: {self.received_chunks_count}/{self.total_chunks}",
                )
            if self.received_bytes != self.file_size:
                self.cleanup()
                return (
                    False,
                    f"Tổng dung lượng thực tế ({self.received_bytes}) không khớp file_size ({self.file_size}).",
                )

            actual_sha256 = self._hasher.hexdigest()
            if actual_sha256.lower() != self.expected_sha256.lower():
                self.cleanup()
                return (
                    False,
                    f"Mã băm SHA-256 không trùng khớp! Kỳ vọng {self.expected_sha256}, Thực tế {actual_sha256}.",
                )

            try:
                with _SAVE_PATH_LOCK:
                    while True:
                        final_path = resolve_unique_save_path(self.save_path)
                        try:
                            os.link(self._temp_part_path, final_path)
                            break
                        except FileExistsError:
                            continue
                    os.remove(self._temp_part_path)
                    self.save_path = final_path
                    self._completed = True
            except OSError as err:
                self.cleanup()
                return False, f"Không thể lưu file hoàn chỉnh xuống đĩa: {err}"

            logger.info(
                "✅ File '%s' đã được ghi và xác thực SHA-256 thành công (%s bytes).",
                os.path.basename(self.save_path),
                self.file_size,
            )
            return True, "File toàn vẹn 100%."
