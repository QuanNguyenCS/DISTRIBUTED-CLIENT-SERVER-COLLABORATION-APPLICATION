"""
Module: common.protocol
Mô tả: Định nghĩa cấu trúc khung gói tin (Packet Framing) và cơ chế đóng gói (pack) /
giải gói (unpack) nhị phân theo giao thức tầng ứng dụng của ứng dụng phân tán.

"""

from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
import time
from typing import Any, Optional, Union

from common.message_types import MessageType
from common.crypto_utils import decrypt_payload, encrypt_payload

# ==============================================================================
# HẰNG SỐ GIAO THỨC (PROTOCOL CONSTANTS)
# ==============================================================================
# Magic Bytes: 2 bytes nhận diện định dạng gói tin riêng của ứng dụng
MAGIC_BYTES: bytes = b"CA"  # Collaboration App

# Phiên bản giao thức hiện tại
PROTOCOL_VERSION: int = 2

# Định dạng nhị phân Header (Network Byte Order - Big Endian "!":
#   2s : 2 bytes magic (b"CA")
#   B  : 1 byte unsigned char (Version)
#   H  : 2 bytes unsigned short (Message Type: 0 - 65535)
#   B  : 1 byte unsigned char (Flags)
#   H  : 2 bytes unsigned short (Reserved)
#   Q  : 8 bytes unsigned long long (Payload Length: 64-bit int)
# Tổng: 2 + 1 + 2 + 1 + 2 + 8 = 16 bytes
HEADER_FORMAT: str = "!2sBHBHQ"
HEADER_SIZE: int = struct.calcsize(HEADER_FORMAT)  # 16 bytes

# Các cờ điều khiển (Flags - 1 byte bitmask)
FLAG_NONE: int = 0x00
FLAG_ENCRYPTED: int = 0x01  # Bit 0: Payload đã được mã hóa bằng AES
FLAG_COMPRESSED: int = 0x02  # Bit 1: Payload đã được nén (dự phòng tương lai)

# Giới hạn an toàn payload tối đa (đề phòng tấn công làm tràn bộ nhớ - DoS)
MAX_PAYLOAD_SIZE: int = 50 * 1024 * 1024  # 50 MB mỗi gói tin
MAX_CONTROL_PAYLOAD_SIZE: int = 64 * 1024
MAX_FILE_FRAME_SIZE: int = 64 * 1024
_ENCRYPTED_CONTEXT = struct.Struct("!BHB")


# ==============================================================================
# CÁC NGOẠI LỆ TỰ ĐỊNH NGHĨA (CUSTOM EXCEPTIONS)
# ==============================================================================
class ProtocolError(Exception):
    """Ngoại lệ cơ sở cho các lỗi vi phạm giao thức."""

    pass


class InvalidMagicBytesError(ProtocolError):
    """Lỗi khi nhận gói tin không bắt đầu bằng Magic Bytes hợp lệ."""

    pass


class UnsupportedVersionError(ProtocolError):
    """Lỗi khi phiên bản gói tin không tương thích."""

    pass


class PayloadTooLargeError(ProtocolError):
    """Lỗi khi độ dài payload vượt quá giới hạn an toàn tối đa."""

    pass


class ConnectionClosedError(Exception):
    """Ngoại lệ ném ra khi kết nối socket bị phía bên kia đóng đột ngột."""

    pass


# ==============================================================================
# LỚP ĐẠI DIỆN GÓI TIN (PACKET DATA CLASS)
# ==============================================================================
@dataclass
class Packet:
    """
    Đại diện cho một gói tin đã được mở gói (unpacked) hoàn chỉnh.
    """

    msg_type: MessageType
    payload: bytes
    flags: int = FLAG_NONE
    version: int = PROTOCOL_VERSION

    @property
    def is_encrypted(self) -> bool:
        """Kiểm tra xem payload có đang được mã hóa hay không."""
        return bool(self.flags & FLAG_ENCRYPTED)

    def to_json(self) -> Any:
        """
        Giải mã payload dạng JSON sang Python dict / list.
        Ném JSONDecodeError nếu payload không phải JSON hợp lệ.
        """
        text_data = self.payload.decode("utf-8")
        return json.loads(text_data)

    def to_text(self) -> str:
        """Giải mã payload dạng chuỗi UTF-8."""
        return self.payload.decode("utf-8")

    def get_decrypted_packet(self, key: bytes) -> Packet:
        """
        Nếu gói tin được mã hóa (FLAG_ENCRYPTED), tiến hành giải mã payload
        và trả về một đối tượng Packet mới với payload đã được giải mã.
        """
        if not self.is_encrypted:
            return self

        decrypted_bytes = decrypt_payload(self.payload, key)
        context = _ENCRYPTED_CONTEXT.pack(self.version, int(self.msg_type), self.flags)
        if not decrypted_bytes.startswith(context):
            raise ProtocolError("Encrypted frame context does not match its header.")
        return Packet(
            msg_type=self.msg_type,
            payload=decrypted_bytes[_ENCRYPTED_CONTEXT.size :],
            flags=self.flags & ~FLAG_ENCRYPTED,
            version=self.version,
        )


# ==============================================================================
# CÁC HÀM XỬ LÝ ĐÓNG GÓI & TRUYỀN NHẬN (PACK / UNPACK / SOCKET IO)
# ==============================================================================
def create_packet(
    msg_type: Union[MessageType, int],
    payload: Union[bytes, str, dict, list] = b"",
    flags: int = FLAG_NONE,
    version: int = PROTOCOL_VERSION,
    encrypt_key: Optional[bytes] = None,
) -> bytes:
    """
    Đóng gói Header nhị phân 16 bytes cùng với Payload thành một chuỗi bytes hoàn chỉnh.
    Hỗ trợ mã hóa đối xứng nếu truyền vào encrypt_key.

    Args:
        msg_type: Loại thông điệp (MessageType enum hoặc int).
        payload: Dữ liệu cần gửi (bytes nhị phân, str văn bản, hoặc dict/list JSON).
        flags: Các cờ bitmask (mã hóa, nén,...).
        version: Phiên bản giao thức (mặc định là 1).
        encrypt_key: Khóa bí mật AES-Fernet nếu muốn mã hóa payload trước khi gửi.

    Returns:
        bytes: Dữ liệu hoàn chỉnh sẵn sàng để gửi qua socket.sendall().
    """
    # 1. Chuẩn hóa payload về dạng bytes
    if isinstance(payload, bytes):
        payload_bytes = payload
    elif isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    elif isinstance(payload, (dict, list)):
        payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    else:
        raise TypeError(
            f"Payload không hợp lệ: {type(payload)}. Phải là bytes, str hoặc dict/list."
        )

    # Mã hóa payload nếu có encrypt_key
    if encrypt_key is not None:
        flags |= FLAG_ENCRYPTED
        context = _ENCRYPTED_CONTEXT.pack(version, int(msg_type), flags)
        payload_bytes = encrypt_payload(context + payload_bytes, encrypt_key)

    payload_len = len(payload_bytes)
    if payload_len > MAX_PAYLOAD_SIZE:
        raise PayloadTooLargeError(
            f"Kích thước payload ({payload_len} bytes) vượt quá ngưỡng an toàn ({MAX_PAYLOAD_SIZE} bytes)."
        )

    # 2. Đóng gói Header 16 bytes bằng struct.pack
    # Định dạng "!2sBHBHQ": Network Byte Order (Big Endian)
    header_bytes = struct.pack(
        HEADER_FORMAT,
        MAGIC_BYTES,
        version,
        int(msg_type),
        flags,
        0,  # Reserved: 2 bytes dự phòng, tạm thời gán 0
        payload_len,
    )

    # 3. Ghép Header và Payload
    return header_bytes + payload_bytes


def recv_exact(
    sock: socket.socket,
    num_bytes: int,
    deadline: Optional[float] = None,
) -> bytes:
    """
    Đọc chính xác và đủ num_bytes từ TCP socket.

    Do đặc tính TCP là Stream of Bytes (luồng byte không phân cách),
    một lệnh sock.recv(N) không đảm bảo trả về đủ N bytes ngay lập tức.
    Hàm này sẽ lặp liên tục cho đến khi gom đủ num_bytes hoặc socket bị ngắt.

    Args:
        sock: Socket TCP đang kết nối.
        num_bytes: Số lượng byte chính xác cần đọc.
        deadline: Mốc time.monotonic() tối đa cho toàn bộ lần đọc (chống slowloris).

    Returns:
        bytes: Đủ num_bytes đã đọc.

    Raises:
        ConnectionClosedError: Nếu đối phương đóng socket trước khi nhận đủ byte.
    """
    buffer = bytearray()
    while len(buffer) < num_bytes:
        if deadline is not None:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise socket.timeout("Handshake/packet read total deadline exceeded.")
            sock.settimeout(remaining_time)

        remaining = num_bytes - len(buffer)
        chunk = sock.recv(remaining)
        if not chunk:
            # sock.recv trả về bytes rỗng (b"") nghĩa là FIN packet đã nhận, socket đã bị ngắt
            raise ConnectionClosedError(
                f"Kết nối bị ngắt đột ngột: Cần {num_bytes} bytes nhưng chỉ nhận được {len(buffer)} bytes."
            )
        buffer.extend(chunk)
    return bytes(buffer)


def recv_packet(
    sock: socket.socket,
    decrypt_key: Optional[bytes] = None,
    max_payload_size: int = MAX_PAYLOAD_SIZE,
    deadline: Optional[float] = None,
) -> Packet:
    """
    Đọc một gói tin hoàn chỉnh từ TCP socket:
      Bước 1: Đọc chính xác 16 bytes Header cố định bằng recv_exact.
      Bước 2: Parse thông tin Header bằng struct.unpack, kiểm tra Magic Bytes và Version.
      Bước 3: Đọc chính xác payload_length bytes tiếp theo bằng recv_exact.
      Bước 4: Giải mã nếu có decrypt_key và cờ FLAG_ENCRYPTED được bật.
      Bước 5: Trả về đối tượng Packet.

    Args:
        sock: Socket TCP đang kết nối.
        decrypt_key: Khóa giải mã AES (nếu muốn tự động giải mã).
        max_payload_size: Ngưỡng payload tối đa cho phép đối với lần đọc này.
        deadline: Mốc time.monotonic() tối đa cho toàn gói tin.

    Returns:
        Packet: Đối tượng gói tin hoàn chỉnh.

    Raises:
        ConnectionClosedError: Khi socket bị đóng.
        InvalidMagicBytesError: Khi nhận phải gói tin rác hoặc từ ứng dụng khác.
        UnsupportedVersionError: Khi phiên bản giao thức không khớp.
        PayloadTooLargeError: Khi kích thước payload vượt ngưỡng cho phép.
    """
    # Bước 1: Đọc 16 bytes Header
    header_bytes = recv_exact(sock, HEADER_SIZE, deadline=deadline)

    # Bước 2: Giải mã Header
    magic, version, raw_msg_type, flags, _reserved, payload_len = struct.unpack(
        HEADER_FORMAT, header_bytes
    )

    # Kiểm tra Magic Bytes
    if magic != MAGIC_BYTES:
        raise InvalidMagicBytesError(
            f"Magic bytes không hợp lệ: nhận được {magic!r}, kỳ vọng {MAGIC_BYTES!r}."
        )

    # Kiểm tra Version
    if version != PROTOCOL_VERSION:
        raise UnsupportedVersionError(
            f"Phiên bản giao thức không tương thích: {version} (hiện tại hỗ trợ: {PROTOCOL_VERSION})."
        )

    if flags & ~FLAG_ENCRYPTED or _reserved != 0:
        raise ProtocolError("Unsupported flags or nonzero reserved field.")

    # Kiểm tra Payload Length
    if payload_len > max_payload_size:
        raise PayloadTooLargeError(
            f"Payload length khai báo ({payload_len} bytes) vượt ngưỡng cho phép ({max_payload_size} bytes)."
        )

    # Bước 3: Đọc Payload Data (nếu có)
    payload_bytes = b""
    if payload_len > 0:
        payload_bytes = recv_exact(sock, payload_len, deadline=deadline)

    # Chuyển raw_msg_type thành MessageType enum nếu có thể
    try:
        msg_type = MessageType(raw_msg_type)
    except ValueError:
        # Nếu gặp mã chưa biết nhưng header vẫn hợp lệ, vẫn giữ dạng int để không crash
        msg_type = raw_msg_type  # type: ignore

    # Bước 4: Tạo Packet object
    packet = Packet(
        msg_type=msg_type,
        payload=payload_bytes,
        flags=flags,
        version=version,
    )

    # Bước 5: Giải mã nếu có decrypt_key
    if decrypt_key is not None and packet.is_encrypted:
        packet = packet.get_decrypted_packet(decrypt_key)

    return packet


def recv_secure_packet(sock, key, **kwargs):
    packet = recv_packet(sock, **kwargs)
    if key is not None:
        if not packet.is_encrypted:
            raise ProtocolError("Encrypted packet required.")
        packet = packet.get_decrypted_packet(key)
    elif packet.is_encrypted:
        raise ProtocolError("No key configured for encrypted packet.")
    return packet
