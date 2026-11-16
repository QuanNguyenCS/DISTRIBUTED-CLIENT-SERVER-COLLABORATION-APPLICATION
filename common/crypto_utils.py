"""
Module: common.crypto_utils
Mô tả: Lớp bảo mật cung cấp các cơ chế mã hóa đối xứng (Symmetric Encryption)
bằng chuẩn AES (sử dụng Fernet - AES-128-CBC kết hợp HMAC-SHA256 để chống giả mạo),
ngăn chặn kẻ xấu nghe lén gói tin trên mạng (Packet Sniffing / Wireshark).
"""

from __future__ import annotations

import base64
from functools import lru_cache
import os
from typing import Optional, Tuple, Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Biến môi trường cấu hình khóa AES dùng chung toàn hệ thống (Server <-> Clients)
ENV_AES_KEY_VAR: str = "COLLAB_AES_KEY"
DEFAULT_SALT: bytes = b"collab_distributed_app_salt_2026"
_P2P_HKDF_INFO: bytes = b"collab-p2p-file-session-v1"


@lru_cache(maxsize=32)
def _derive_key_cached(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def derive_key(passphrase: str, salt: bytes = DEFAULT_SALT) -> bytes:
    """
    Sinh khóa bảo mật 32-bytes chuẩn URL-safe Base64 từ chuỗi mật khẩu
    bằng thuật toán KDF (PBKDF2HMAC với 100,000 vòng lặp băm SHA-256).
    """
    return _derive_key_cached(passphrase, salt)


def get_shared_app_key(secret_or_key: Optional[str] = None) -> bytes:
    raw_value = (
        secret_or_key
        if secret_or_key is not None
        else os.environ.get(ENV_AES_KEY_VAR, "")
    ).strip()
    if not raw_value:
        raise ValueError(
            "Set COLLAB_AES_KEY to a private shared room secret before starting the application."
        )

    try:
        candidate = raw_value.encode("ascii")
        Fernet(candidate)
        return candidate
    except Exception:
        return derive_key(raw_value)


def generate_ephemeral_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, str]:
    """
    Sinh cặp khóa bất đối xứng X25519 tạm thời (ephemeral) cho mỗi phiên truyền file P2P.
    Returns:
        Tuple[X25519PrivateKey, str]: (private_key giữ trong RAM, public_key base64 gửi qua mạng).
    """
    priv_key = x25519.X25519PrivateKey.generate()
    pub_bytes = priv_key.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    return priv_key, pub_b64


def derive_p2p_session_key(
    private_key: x25519.X25519PrivateKey,
    peer_public_b64: str,
) -> bytes:
    """
    Tính toán khóa phiên AES-Fernet tạm thời (chỉ dùng cho 1 phiên P2P duy nhất)
    từ khóa bí mật X25519 cục bộ và khóa công khai X25519 của đối phương qua HKDF-SHA256.
    """
    peer_pub_raw = base64.b64decode(peer_public_b64.encode("ascii"), validate=True)
    if len(peer_pub_raw) != 32:
        raise ValueError("Khóa công khai X25519 phải có độ dài chính xác 32 bytes.")
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_raw)
    shared_secret = private_key.exchange(peer_pub)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_P2P_HKDF_INFO,
    ).derive(shared_secret)
    return base64.urlsafe_b64encode(derived)


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
