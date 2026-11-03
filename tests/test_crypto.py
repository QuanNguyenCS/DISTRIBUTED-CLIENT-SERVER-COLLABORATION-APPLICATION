"""
Unit & Integration Tests cho Giai đoạn 8: Lớp Bảo mật & Mã hóa Dữ liệu (Security Layer - AES/Fernet)
Kiểm tra toàn diện:
  1. Sinh khóa & dẫn xuất khóa chuẩn PBKDF2HMAC (Derive Key).
  2. Mã hóa & giải mã chuỗi bytes / chuỗi ký tự bằng AES.
  3. Kiểm tra tính toàn vẹn (HMAC-SHA256): Dữ liệu bị can thiệp/sửa đổi trên đường truyền sẽ bị ném lỗi.
  4. Đóng gói Packet có cờ FLAG_ENCRYPTED: Payload trong luồng raw socket hoàn toàn bị mã hóa.
  5. Truyền thông mã hóa đầu-cuối giữa 2 Client qua Server.
"""

import socket
import threading
import time
import pytest
from cryptography.fernet import InvalidToken

from common.crypto_utils import (
    decrypt_payload,
    derive_key,
    encrypt_payload,
    generate_random_key,
)
from common.message_types import MessageType
from common.protocol import (
    FLAG_ENCRYPTED,
    create_packet,
    recv_packet,
)
from server.server_core import ServerCore
from client.client_core import ClientCore


def get_free_port() -> int:
    """Lấy cổng mạng rảnh trên localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestCryptoUnit:
    """Kiểm thử đơn vị các hàm mật mã học."""

    def test_key_derivation_deterministic(self):
        """Cùng một mật khẩu và salt luôn sinh ra cùng một khóa AES 32-bytes."""
        key1 = derive_key("MySecretPassword123")
        key2 = derive_key("MySecretPassword123")
        assert key1 == key2
        assert len(key1) == 44  # Base64 encoding of 32 bytes = 44 chars

        key_diff = derive_key("DifferentPassword456")
        assert key1 != key_diff

    def test_encrypt_and_decrypt_payload(self):
        """Mã hóa và giải mã chuỗi văn bản và nhị phân."""
        key = generate_random_key()
        original_text = "Tin nhắn tuyệt mật: Tọa độ 10.7769N, 106.7009E"

        cipher = encrypt_payload(original_text, key)
        # Kiểm tra ciphertext không chứa nội dung gốc
        assert original_text.encode("utf-8") not in cipher

        # Giải mã
        decrypted = decrypt_payload(cipher, key)
        assert decrypted.decode("utf-8") == original_text

    def test_tampered_ciphertext_fails_integrity(self):
        """Dữ liệu bị sửa đổi trên đường truyền (Man-in-the-Middle) sẽ bị phát hiện và từ chối."""
        key = generate_random_key()
        cipher = bytearray(encrypt_payload("Dữ liệu an toàn", key))

        # Giả lập kẻ xấu sửa đổi 1 byte trong ciphertext
        cipher[15] ^= 0xFF

        with pytest.raises(InvalidToken):
            decrypt_payload(bytes(cipher), key)

    def test_packet_creation_with_encryption(self):
        """Gói tin tạo ra có cờ FLAG_ENCRYPTED và payload được mã hóa."""
        key = derive_key("RoomKey2026")
        secret_message = "Hello Confidential World"

        packet_bytes = create_packet(
            MessageType.CHAT_BROADCAST,
            secret_message,
            encrypt_key=key,
        )

        # Đảm bảo không tìm thấy chuỗi gốc trong raw packet bytes
        assert secret_message.encode("utf-8") not in packet_bytes

        # Đọc gói tin qua memory/socket
        s1, s2 = socket.socketpair()
        s1.sendall(packet_bytes)
        pkt = recv_packet(s2)
        assert pkt.is_encrypted is True

        # Giải mã
        decrypted_pkt = pkt.get_decrypted_packet(key)
        assert decrypted_pkt.is_encrypted is False
        assert decrypted_pkt.to_text() == secret_message

        s1.close()
        s2.close()


class TestCryptoIntegration:
    """Kiểm thử tích hợp mã hóa đầu-cuối giữa 2 Client."""

    def test_encrypted_communication_between_clients(self):
        """Alice và Bob bật mã hóa với cùng khóa bí mật, trao đổi tin nhắn thành công."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)

        # Cả Server và Client cùng bật mã hóa phòng chat với mật khẩu chung
        shared_pass = "ProjectCollabPassphrase2026"
        server.enable_encryption(shared_pass)
        alice.enable_encryption(shared_pass)
        bob.enable_encryption(shared_pass)

        assert alice.connect() and alice.authenticate("AliceSecure")[0]
        assert bob.connect() and bob.authenticate("BobSecure")[0]

        bob_received_direct = []
        bob.register_callback(
            MessageType.CHAT_DIRECT,
            lambda pkt: bob_received_direct.append(pkt.to_json()),
        )

        secret_text = "Nội dung này được bảo vệ bởi AES-256!"
        assert alice.send_direct_message(recipient="BobSecure", content=secret_text) is True

        time.sleep(0.5)

        assert len(bob_received_direct) == 1
        assert bob_received_direct[0]["content"] == secret_text
        assert bob_received_direct[0]["sender"] == "AliceSecure"

        alice.disconnect()
        bob.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_encrypted_broadcast_communication(self):
        """Alice phát tin nhắn chung mã hóa, Bob giải mã thành công."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        shared_pass = "SecureRoomPass123"
        server.enable_encryption(shared_pass)

        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        alice.enable_encryption(shared_pass)
        bob.enable_encryption(shared_pass)

        assert alice.connect() and alice.authenticate("AliceBC")[0]
        assert bob.connect() and bob.authenticate("BobBC")[0]

        bob_received = []
        bob.register_callback(
            MessageType.CHAT_BROADCAST,
            lambda pkt: bob_received.append(pkt.to_json()),
        )

        broadcast_text = "Chào toàn thể anh em trong phòng chat bảo mật!"
        assert alice.send_broadcast(broadcast_text) is True

        time.sleep(0.5)

        assert len(bob_received) == 1
        assert bob_received[0]["content"] == broadcast_text
        assert bob_received[0]["sender"] == "AliceBC"

        alice.disconnect()
        bob.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_eavesdropper_without_key_cannot_read_payload(self):
        """Kẻ nghe lén (Sniffer) không có key bí mật chỉ nhận được cờ FLAG_ENCRYPTED và byte rác."""
        key = derive_key("TopSecretKey999")
        plain = "Thông điệp cơ mật không thể xem trộm"
        pkt_bytes = create_packet(MessageType.CHAT_BROADCAST, plain, encrypt_key=key)

        s1, s2 = socket.socketpair()
        s1.sendall(pkt_bytes)
        # Sniffer đọc gói tin mà KHÔNG có key
        sniffed_pkt = recv_packet(s2)

        assert sniffed_pkt.is_encrypted is True
        # Sniffer cố ép đọc JSON hoặc text sẽ nhận byte mã hóa Fernet không đọc được bản rõ
        assert plain.encode("utf-8") not in sniffed_pkt.payload
        # Giải mã bằng key sai sẽ ném ngoại lệ
        wrong_key = derive_key("WrongPassword000")
        with pytest.raises(InvalidToken):
            sniffed_pkt.get_decrypted_packet(wrong_key)

        s1.close()
        s2.close()
