"""
Module: common.crypto_utils
Mô tả: Lớp bảo mật cung cấp các cơ chế mã hóa đối xứng (Symmetric Encryption)
bằng chuẩn AES (sử dụng Fernet - AES-128-CBC kết hợp HMAC-SHA256 để chống giả mạo),
ngăn chặn kẻ xấu nghe lén gói tin trên mạng (Packet Sniffing / Wireshark).
"""

from __future__ import annotations

import base64
import os
from typing import Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Khóa bí mật mặc định dùng chung cho ứng dụng (Pre-Shared Key)
DEFAULT_SHARED_SECRET: str = "CollabSecretKey2026@SecureNetworkApplication"
DEFAULT_SALT: bytes = b"collab_distributed_app_salt_2026"


def derive_key(passphrase: str = DEFAULT_SHARED_SECRET, salt: bytes = DEFAULT_SALT) -> bytes:
    """
    Sinh khóa bảo mật 32-bytes chuẩn URL-safe Base64 từ mật khẩu văn bản
    bằng thuật toán KDF (PBKDF2HMAC với 100,000 vòng lặp băm SHA-256).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
    return key


def generate_random_key() -> bytes:
    """Sinh ngẫu nhiên một khóa Fernet 256-bit mới."""
    return Fernet.generate_key()


def encrypt_payload(data: Union[bytes, str], key: bytes) -> bytes:
    """
    Mã hóa chuỗi bytes hoặc văn bản bằng thuật toán đối xứng AES-Fernet.

    Args:
        data: Dữ liệu thô cần mã hóa (bytes hoặc str).
        key: Khóa bí mật 32-bytes urlsafe base64.

    Returns:
        bytes: Dữ liệu mã hóa (Ciphertext / Token).
    """
    if isinstance(data, str):
        raw_bytes = data.encode("utf-8")
    else:
        raw_bytes = data

    f = Fernet(key)
    return f.encrypt(raw_bytes)


def decrypt_payload(cipher_bytes: bytes, key: bytes) -> bytes:
    """
    Giải mã chuỗi bytes mã hóa về dữ liệu gốc và kiểm tra chữ ký HMAC.

    Args:
        cipher_bytes: Dữ liệu đã mã hóa.
        key: Khóa bí mật đã dùng để mã hóa.

    Returns:
        bytes: Dữ liệu thô nguyên bản.

    Raises:
        InvalidToken: Nếu khóa không đúng hoặc dữ liệu bị sửa đổi trên đường truyền.
    """
    f = Fernet(key)
    return f.decrypt(cipher_bytes)
