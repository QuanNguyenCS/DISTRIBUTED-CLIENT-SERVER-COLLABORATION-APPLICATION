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

    def test_e2ee_chat_without_server_encryption(self):
        """Server chạy chế độ thường (không --passphrase), 2 Client bật AES vẫn chat chung & riêng bình thường."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)

        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        alice.enable_encryption("RoomE2EEPass123")
        bob.enable_encryption("RoomE2EEPass123")

        try:
            assert alice.connect() and alice.authenticate("AliceE2EE")[0]
            assert bob.connect() and bob.authenticate("BobE2EE")[0]
            assert alice.server_encryption_enabled is False
            assert bob.server_encryption_enabled is False

            bc_event = threading.Event()
            dm_event = threading.Event()
            bob_broadcasts = []
            bob_directs = []

            bob.register_callback(
                MessageType.CHAT_BROADCAST,
                lambda pkt: (bob_broadcasts.append(pkt.to_json()), bc_event.set()),
            )
            bob.register_callback(
                MessageType.CHAT_DIRECT,
                lambda pkt: (bob_directs.append(pkt.to_json()), dm_event.set()),
            )

            assert alice.send_broadcast("Tin nhắn chung E2EE không cần key server") is True
            assert bc_event.wait(timeout=2.0)
            assert bob_broadcasts[0]["content"] == "Tin nhắn chung E2EE không cần key server"
            assert bob_broadcasts[0]["sender"] == "AliceE2EE"

            assert alice.send_direct_message("BobE2EE", "Tin nhắn riêng E2EE bí mật") is True
            assert dm_event.wait(timeout=2.0)
            assert bob_directs[0]["content"] == "Tin nhắn riêng E2EE bí mật"
            assert bob_directs[0]["sender"] == "AliceE2EE"
            assert bob_directs[0]["recipient"] == "BobE2EE"
        finally:
            alice.disconnect()
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_e2ee_file_transfer_without_server_encryption(self, tmp_path):
        """Server chạy chế độ thường, 2 Client bật AES vẫn gửi file nhị phân & file 0-byte toàn vẹn SHA-256."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)

        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = str(tmp_path / "downloads")
        alice.enable_encryption("FileE2EEPass456")
        bob.enable_encryption("FileE2EEPass456")

        try:
            assert alice.connect() and alice.authenticate("AliceFileE2EE")[0]
            assert bob.connect() and bob.authenticate("BobFileE2EE")[0]

            received = []
            recv_event = threading.Event()

            def on_recv(sender, file_name, save_path):
                received.append((sender, file_name, save_path))
                recv_event.set()

            bob.on_file_received = on_recv

            raw_data = bytes(range(256)) * 300  # 76,800 bytes (3 chunks)
            src_file = tmp_path / "photo.jpg"
            src_file.write_bytes(raw_data)

            ok, msg = alice.send_file("BobFileE2EE", str(src_file), timeout=5.0)
            assert ok is True, msg
            assert recv_event.wait(timeout=2.0)
            assert received[0][0] == "AliceFileE2EE"
            assert received[0][1] == "photo.jpg"
            assert (tmp_path / "downloads" / "photo.jpg").read_bytes() == raw_data

            # Kiểm tra gửi file rỗng 0-byte qua kênh E2EE
            recv_event.clear()
            empty_file = tmp_path / "empty.txt"
            empty_file.write_bytes(b"")
            ok_empty, msg_empty = alice.send_file("BobFileE2EE", str(empty_file), timeout=5.0)
            assert ok_empty is True, msg_empty
            assert recv_event.wait(timeout=2.0)
            assert (tmp_path / "downloads" / "empty.txt").read_bytes() == b""
        finally:
            alice.disconnect()
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_mismatched_key_e2ee_negative_cases(self, tmp_path):
        """Hai Client khác mật khẩu AES: không văng chuỗi mã hóa vào chat, không crash luồng nhận, báo lỗi rõ ràng."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)

        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = str(tmp_path / "downloads")
        alice.enable_encryption("PasswordOne")
        bob.enable_encryption("PasswordTwoMismatch")

        try:
            assert alice.connect() and alice.authenticate("AliceMismatch")[0]
            assert bob.connect() and bob.authenticate("BobMismatch")[0]

            err_event = threading.Event()
            err_notices = []
            bc_msgs = []
            dm_msgs = []
            file_errors = []
            file_ok_calls = []

            bob.register_callback(
                MessageType.ERROR_NOTICE,
                lambda pkt: (err_notices.append(pkt.to_json()), err_event.set()),
            )
            bob.register_callback(MessageType.CHAT_BROADCAST, lambda pkt: bc_msgs.append(pkt.to_json()))
            bob.register_callback(MessageType.CHAT_DIRECT, lambda pkt: dm_msgs.append(pkt.to_json()))
            bob.on_file_error = lambda sender, fname, reason: file_errors.append((sender, fname, reason))
            bob.on_file_received = lambda sender, fname, path: file_ok_calls.append((sender, fname, path))

            # 1. Broadcast sai key
            assert alice.send_broadcast("Bi mat 1") is True
            assert err_event.wait(timeout=2.0)
            assert err_notices[-1]["code"] == "DECRYPTION_FAILED"
            assert len(bc_msgs) == 0
            assert bob.is_connected is True

            # 2. Direct sai key
            err_event.clear()
            assert alice.send_direct_message("BobMismatch", "Bi mat 2") is True
            assert err_event.wait(timeout=2.0)
            assert err_notices[-1]["code"] == "DECRYPTION_FAILED"
            assert len(dm_msgs) == 0
            assert bob.is_connected is True

            # 3. File transfer sai key
            secret_file = tmp_path / "secret.bin"
            secret_file.write_bytes(b"SecretBinaryContent" * 20)
            ok, msg = alice.send_file("BobMismatch", str(secret_file), timeout=5.0)
            assert ok is False
            assert len(file_errors) >= 1
            assert len(file_ok_calls) == 0
            assert bob.is_connected is True
        finally:
            alice.disconnect()
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_p2p_encrypted_file_missing_key_and_wire_security(self, tmp_path):
        """Gửi file P2P bật AES: bên nhận chưa nhập key phải báo lỗi rõ & gói P2P trên wire mang FLAG_ENCRYPTED."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = str(tmp_path / "downloads")
        alice.enable_encryption("P2PSecretKey")

        # Kiểm tra wire packet từ Alice tới fake P2P sniffer mang FLAG_ENCRYPTED, không lộ plaintext
        sniffed_packets = []
        sniffer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sniffer_sock.bind(("127.0.0.1", 0))
        sniffer_sock.listen(4)
        sniff_port = sniffer_sock.getsockname()[1]

        def run_sniffer():
            conn, _ = sniffer_sock.accept()
            with conn:
                pkt1 = recv_packet(conn)
                sniffed_packets.append(pkt1)
                conn.sendall(
                    create_packet(MessageType.PEER_HELLO_ACK, {"status": "OK", "username": "Sniffer", "protocol_version": 1})
                )
                pkt2 = recv_packet(conn)
                sniffed_packets.append(pkt2)
                offer = pkt2.to_json()
                conn.sendall(
                    create_packet(
                        MessageType.FILE_OFFER_RESP,
                        {"file_id": offer["file_id"], "sender": "Alice", "recipient": "Sniffer", "status": "ACCEPTED"},
                    )
                )
                pkt3 = recv_packet(conn)
                sniffed_packets.append(pkt3)
                conn.sendall(
                    create_packet(
                        MessageType.FILE_ACK,
                        {"file_id": offer["file_id"], "sender": "Alice", "recipient": "Sniffer", "status": "SUCCESS", "reason": "OK"},
                    )
                )

        try:
            assert alice.connect() and alice.authenticate("AliceSecP2P")[0]
            assert bob.connect() and bob.authenticate("BobNoKeyP2P")[0]

            file_errors = []
            bob.on_file_error = lambda sender, fname, reason: file_errors.append((sender, fname, reason))

            secret_file = tmp_path / "secret_p2p.txt"
            secret_text = b"TOP_SECRET_P2P_BINARY_PAYLOAD_DO_NOT_LEAK"
            secret_file.write_bytes(secret_text)

            # Bob chưa nhập key -> reject ngay tại FILE_OFFER_REQ
            ok, reason = alice.send_file("BobNoKeyP2P", str(secret_file), timeout=5.0)
            assert ok is False
            assert "mật khẩu phòng" in reason
            assert len(file_errors) == 1
            assert not (tmp_path / "downloads" / "secret_p2p.txt").exists()

            # Xác minh packet FILE_CHUNK gửi trên P2P TCP bị mã hóa hoàn toàn
            sniff_thread = threading.Thread(target=run_sniffer, daemon=True)
            sniff_thread.start()

            # Đăng ký endpoint trỏ sang sniffer trên Tracker
            server.session_mgr.register_user("WireSniffer", object(), ("127.0.0.1", 55555), p2p_port=sniff_port)
            ok_wire, _ = alice.send_file("WireSniffer", str(secret_file), timeout=5.0)
            sniff_thread.join(timeout=2.0)

            assert ok_wire is True
            chunk_pkt = sniffed_packets[-1]
            assert chunk_pkt.msg_type == MessageType.FILE_CHUNK
            assert chunk_pkt.is_encrypted is True
            assert secret_text not in chunk_pkt.payload
        finally:
            sniffer_sock.close()
            server.session_mgr.unregister_user("WireSniffer")
            alice.disconnect()
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)
