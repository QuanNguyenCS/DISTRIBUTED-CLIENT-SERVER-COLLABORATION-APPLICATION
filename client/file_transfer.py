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
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Generator, Optional, Tuple

from common.logger import get_logger

logger = get_logger("client.file")

# Kích thước chuẩn mỗi chunk: 32 KB (32768 bytes)
DEFAULT_CHUNK_SIZE: int = 32 * 1024


def calculate_file_hash(file_path: str | Path) -> str:
    """
    Tính mã băm SHA-256 của một file trên đĩa cứng bằng cách đọc tuần tự theo khối.
    Tối ưu bộ nhớ RAM ngay cả với file dung lượng hàng trăm MB.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(64 * 1024):
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
    """Theo dõi tiến trình nhận một file từ người gửi."""
    file_id: str
    sender: str
    file_name: str
    file_size: int
    total_chunks: int
    expected_sha256: str
    save_path: str
    received_chunks: Dict[int, bytes] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)

    @property
    def progress_percentage(self) -> float:
        """Phần trăm hoàn thành từ 0.0 đến 100.0."""
        if self.total_chunks == 0:
            return 100.0
        return (len(self.received_chunks) / self.total_chunks) * 100.0

    def add_chunk(self, chunk_index: int, chunk_data: bytes) -> bool:
        """Lưu một mảnh chunk nhận được."""
        self.received_chunks[chunk_index] = chunk_data
        return len(self.received_chunks) == self.total_chunks

    def assemble_and_verify(self) -> Tuple[bool, str]:
        """
        Ghép tất cả các chunk lại thành file hoàn chỉnh và kiểm tra mã băm SHA-256.
        
        Returns:
            Tuple[bool, str]: (Thành công hay không, Thông báo kết quả / Lý do).
        """
        if len(self.received_chunks) != self.total_chunks:
            return False, f"Chưa nhận đủ chunk: {len(self.received_chunks)}/{self.total_chunks}"

        # Đảm bảo thư mục lưu file tồn tại
        os.makedirs(os.path.dirname(os.path.abspath(self.save_path)), exist_ok=True)

        # Ghi các chunk theo đúng thứ tự 0 -> total_chunks - 1
        with open(self.save_path, "wb") as f:
            for i in range(self.total_chunks):
                chunk = self.received_chunks.get(i)
                if chunk is None:
                    return False, f"Thiếu mảnh chunk số {i}"
                f.write(chunk)

        # Tính lại SHA-256 để đối chiếu bit-by-bit
        actual_sha256 = calculate_file_hash(self.save_path)
        if actual_sha256.lower() != self.expected_sha256.lower():
            return False, f"Mã băm SHA-256 không trùng khớp! Kỳ vọng {self.expected_sha256}, Thực tế {actual_sha256}."

        logger.info(
            "✅ File '%s' đã được ghép và xác thực SHA-256 thành công (%s bytes).",
            self.file_name,
            self.file_size,
        )
        return True, "File toàn vẹn 100%."
