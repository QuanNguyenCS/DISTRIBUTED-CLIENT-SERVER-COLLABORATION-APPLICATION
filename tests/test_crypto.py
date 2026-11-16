"""
Unit & Integration Tests cho Lớp Bảo mật Tự động:
  1. Khóa AES-Fernet dùng chung toàn hệ thống nạp từ biến môi trường COLLAB_AES_KEY (có mặc định sẵn).
  2. Bảo vệ toàn diện Control + Data Plane trên kênh Server <-> Client (AUTH, Tracker, Chat, CHAT_ACK).
  3. Chống hạ cấp gói tin bản rõ (Anti-Downgrade: ENCRYPTION_REQUIRED).
  4. Trao đổi khóa bất đối xứng X25519 tạm thời (Ephemeral ECDH) cho mỗi phiên P2P File Transfer:
     PEER_HELLO/ACK bọc khóa chung; FILE_OFFER/FILE_CHUNK/FILE_ACK dùng khóa phiên tạm riêng (Forward Secrecy).
"""

import socket
import threading
import time
import pytest
from cryptography.fernet import Fernet, InvalidToken

from common.crypto_utils import (
    ENV_AES_KEY_VAR,
    decrypt_payload,
    derive_key,
    derive_p2p_session_key,
    encrypt_payload,
    generate_ephemeral_x25519_keypair,
    generate_random_key,
    get_shared_app_key,
)
from common.message_types import MessageType
from common.protocol import (
    ConnectionClosedError,
    PROTOCOL_VERSION,
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
    """Kiểm thử đơn vị các hàm mật mã học dùng chung và X25519 P2P."""

    def test_key_derivation_deterministic(self):
        """Cùng một mật khẩu và salt luôn sinh ra cùng một khóa AES 32-bytes."""
        key1 = derive_key("MySecretPassword123")
        key2 = derive_key("MySecretPassword123")
        assert key1 == key2
        assert len(key1) == 44

        key_diff = derive_key("DifferentPassword456")
        assert key1 != key_diff

    def test_shared_app_key_from_env_and_fallback(self, monkeypatch):
        """Biến môi trường COLLAB_AES_KEY hỗ trợ cả chuỗi bất kỳ lẫn Fernet key sẵn; rỗng sẽ dùng khóa mặc định."""
        monkeypatch.delenv(ENV_AES_KEY_VAR, raising=False)
        with pytest.raises(ValueError, match="COLLAB_AES_KEY"):
            get_shared_app_key()

        monkeypatch.setenv(ENV_AES_KEY_VAR, "CustomTeamEnvSecret")
        env_derived = get_shared_app_key()
        assert env_derived == derive_key("CustomTeamEnvSecret")

        raw_fernet = Fernet.generate_key().decode("ascii")
        monkeypatch.setenv(ENV_AES_KEY_VAR, raw_fernet)
        assert get_shared_app_key() == raw_fernet.encode("ascii")

    def test_ephemeral_x25519_session_key_exchange(self):
        """Hai peer tạo cặp khóa X25519 ngẫu nhiên sẽ tính ra cùng 1 khóa phiên và khác nhau ở mỗi lần chạy."""
        priv_a, pub_a = generate_ephemeral_x25519_keypair()
        priv_b, pub_b = generate_ephemeral_x25519_keypair()

        sess_a = derive_p2p_session_key(priv_a, pub_b)
        sess_b = derive_p2p_session_key(priv_b, pub_a)
        assert sess_a == sess_b
        assert len(sess_a) == 44

        # Phiên mới sinh khóa hoàn toàn khác (Forward Secrecy)
        priv_c, _ = generate_ephemeral_x25519_keypair()
        priv_d, pub_d = generate_ephemeral_x25519_keypair()
        assert derive_p2p_session_key(priv_c, pub_d) != sess_a

        with pytest.raises(Exception):
            derive_p2p_session_key(priv_a, "invalid-base64!")

    def test_encrypt_and_decrypt_payload(self):
        """Mã hóa và giải mã chuỗi văn bản bằng Fernet."""
        key = generate_random_key()
        original_text = "Tin nhắn tuyệt mật: Tọa độ 10.7769N, 106.7009E"
        cipher = encrypt_payload(original_text, key)
        assert original_text.encode("utf-8") not in cipher
        assert decrypt_payload(cipher, key).decode("utf-8") == original_text

    def test_tampered_ciphertext_fails_integrity(self):
        """Dữ liệu bị sửa đổi trên đường truyền (HMAC) sẽ ném InvalidToken."""
        key = generate_random_key()
        cipher = bytearray(encrypt_payload("Dữ liệu an toàn", key))
        cipher[15] ^= 0xFF
        with pytest.raises(InvalidToken):
            decrypt_payload(bytes(cipher), key)

    def test_packet_creation_with_encryption(self):
        """Gói tin tạo ra mang FLAG_ENCRYPTED và che giấu hoàn toàn bản rõ trên socket."""
        key = get_shared_app_key()
        secret_message = "Hello Confidential World"
        packet_bytes = create_packet(
            MessageType.CHAT_BROADCAST, secret_message, encrypt_key=key
        )
        assert secret_message.encode("utf-8") not in packet_bytes

        s1, s2 = socket.socketpair()
        s1.sendall(packet_bytes)
        pkt = recv_packet(s2)
        assert pkt.is_encrypted is True
        decrypted_pkt = pkt.get_decrypted_packet(key)
        assert decrypted_pkt.is_encrypted is False
        assert decrypted_pkt.to_text() == secret_message
        s1.close()
        s2.close()


class TestCryptoIntegration:
    """Kiểm thử tích hợp cơ chế mã hóa tự động toàn hệ thống và X25519 P2P."""

    def test_auto_encryption_enabled_out_of_the_box(self, tmp_path):
        """Không cần nhập passphrase: ServerCore() và ClientCore() tự mã hóa toàn bộ Chat, Direct & P2P File."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = str(tmp_path / "downloads")

        try:
            assert alice.connect() and alice.authenticate("AliceAuto")[0]
            assert bob.connect() and bob.authenticate("BobAuto")[0]
            assert alice.server_encryption_enabled is True
            assert bob.server_encryption_enabled is True

            bc_msgs, dm_msgs, acks = [], [], []
            bc_ev, dm_ev, ack_ev = (
                threading.Event(),
                threading.Event(),
                threading.Event(),
            )
            bob.register_callback(
                MessageType.CHAT_BROADCAST,
                lambda p: (bc_msgs.append(p.to_json()), bc_ev.set()),
            )
            bob.register_callback(
                MessageType.CHAT_DIRECT,
                lambda p: (dm_msgs.append(p.to_json()), dm_ev.set()),
            )
            alice.register_callback(
                MessageType.CHAT_ACK, lambda p: (acks.append(p.to_json()), ack_ev.set())
            )

            assert alice.send_broadcast("Xin chao ma hoa tu dong") is True
            assert bc_ev.wait(timeout=2.0)
            assert bc_msgs[0]["content"] == "Xin chao ma hoa tu dong"

            assert (
                alice.send_direct_message("BobAuto", "Tin rieng khong can nhap pass")
                is True
            )
            assert dm_ev.wait(timeout=2.0) and ack_ev.wait(timeout=2.0)
            assert dm_msgs[0]["content"] == "Tin rieng khong can nhap pass"
            assert "content" not in acks[0]

            sample_file = tmp_path / "auto_secret.bin"
            raw = b"AUTO_P2P_X25519_PAYLOAD_" * 500
            sample_file.write_bytes(raw)
            ok, msg = alice.send_file("BobAuto", str(sample_file), timeout=5.0)
            assert ok is True, msg
            assert (tmp_path / "downloads" / "auto_secret.bin").read_bytes() == raw
        finally:
            alice.disconnect()
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_env_var_aes_key_override_between_server_and_clients(self, monkeypatch):
        """Thay đổi COLLAB_AES_KEY trên env áp dụng tức thì; Client khác khóa env sẽ bị DECRYPTION_FAILED."""
        monkeypatch.setenv(ENV_AES_KEY_VAR, "EnvRoomKey_2026_Prod")
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        good_client = ClientCore(server_host="127.0.0.1", server_port=port)
        wrong_client = ClientCore(server_host="127.0.0.1", server_port=port)
        wrong_client.enable_encryption("DifferentWrongEnvKey")

        try:
            assert good_client.connect() and good_client.authenticate("EnvMatchUser")[0]
            assert wrong_client.connect()

            wrong_errors = []
            err_ev = threading.Event()
            wrong_client.register_callback(
                MessageType.ERROR_NOTICE,
                lambda p: (wrong_errors.append(p.to_json()), err_ev.set()),
            )
            # wrong_client gửi AUTH_REQ mã hóa bằng khóa sai -> Server báo DECRYPTION_FAILED ngay
            ok_wrong, _ = wrong_client.authenticate("WrongEnvUser", timeout=1.5)
            assert ok_wrong is False
            assert err_ev.wait(timeout=2.0) is True
            assert wrong_errors[-1]["code"] == "DECRYPTION_FAILED"
        finally:
            good_client.disconnect()
            wrong_client.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_eavesdropper_without_key_cannot_read_payload(self):
        """Kẻ nghe lén bắt được raw socket bytes không thể đọc bản rõ hoặc giải mã bằng khóa sai."""
        key = get_shared_app_key()
        plain = "Thông điệp cơ mật không thể xem trộm"
        pkt_bytes = create_packet(MessageType.CHAT_BROADCAST, plain, encrypt_key=key)

        s1, s2 = socket.socketpair()
        s1.sendall(pkt_bytes)
        sniffed_pkt = recv_packet(s2)

        assert sniffed_pkt.is_encrypted is True
        assert plain.encode("utf-8") not in sniffed_pkt.payload
        with pytest.raises(InvalidToken):
            sniffed_pkt.get_decrypted_packet(derive_key("AttackerWrongKey"))

        s1.close()
        s2.close()

    def test_server_blocks_plaintext_downgrade_on_auth_and_chat(self):
        """Client tắt mã hóa cố gửi bản rõ AUTH_REQ / CHAT_BROADCAST phải bị chặn với ENCRYPTION_REQUIRED."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        enc_alice = ClientCore(server_host="127.0.0.1", server_port=port)
        plain_attacker = ClientCore(
            server_host="127.0.0.1", server_port=port, auto_encrypt=False
        )

        try:
            assert enc_alice.connect() and enc_alice.authenticate("AliceStrict")[0]
            assert plain_attacker.connect()

            atk_errors = []
            err_ev = threading.Event()
            plain_attacker.register_callback(
                MessageType.ERROR_NOTICE,
                lambda p: (atk_errors.append(p.to_json()), err_ev.set()),
            )

            ok_plain, _ = plain_attacker.authenticate("PlainAttacker", timeout=1.5)
            assert ok_plain is False
            assert err_ev.wait(timeout=2.0)
            assert atk_errors[-1]["code"] == "ENCRYPTION_REQUIRED"
        finally:
            enc_alice.disconnect()
            plain_attacker.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_p2p_ephemeral_x25519_wire_forward_secrecy(self, tmp_path):
        """
        Kiểm chứng Wire Forward Secrecy cho P2P File Transfer:
          - PEER_HELLO / PEER_HELLO_ACK mang x25519_pub và được bọc bằng khóa AES chung.
          - FILE_OFFER_REQ / FILE_CHUNK / FILE_ACK dùng khóa AES tạm X25519: ngay cả dùng khóa AES chung
            của ứng dụng cũng KHÔNG giải mã được FILE_OFFER hay FILE_CHUNK (InvalidToken), và 2 lần gửi
            tạo khóa/ciphertext khác nhau!
        """
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = str(tmp_path / "downloads")

        captured_c2s = []
        captured_s2c = []

        try:
            assert alice.connect() and alice.authenticate("AliceFS")[0]
            assert bob.connect() and bob.authenticate("BobFS")[0]

            # Tạo TCP sniffer proxy đứng giữa Alice và Bob P2P Listener
            proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_sock.bind(("127.0.0.1", 0))
            proxy_sock.listen(4)
            proxy_port = proxy_sock.getsockname()[1]

            def run_mitm_sniffer():
                in_conn, _ = proxy_sock.accept()
                out_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                out_conn.connect(("127.0.0.1", bob.p2p_port))

                def pipe(src, dst, bucket):
                    try:
                        while True:
                            pkt = recv_packet(src)
                            bucket.append(pkt)
                            # Forward nguyên trạng header + payload
                            dst.sendall(
                                create_packet(
                                    pkt.msg_type,
                                    pkt.payload,
                                    flags=pkt.flags,
                                    version=pkt.version,
                                )
                            )
                    except Exception:
                        pass

                t_a = threading.Thread(
                    target=pipe, args=(in_conn, out_conn, captured_c2s), daemon=True
                )
                t_b = threading.Thread(
                    target=pipe, args=(out_conn, in_conn, captured_s2c), daemon=True
                )
                t_a.start()
                t_b.start()
                t_a.join(timeout=4.0)
                t_b.join(timeout=4.0)
                in_conn.close()
                out_conn.close()

            proxy_thread = threading.Thread(target=run_mitm_sniffer, daemon=True)
            proxy_thread.start()

            # Trỏ Tracker của ProxyBob sang cổng proxy sniffer
            server.session_mgr.get_session("BobFS").p2p_port = proxy_port

            secret_file = tmp_path / "forward_secret.txt"
            secret_bytes = b"TOP_SECRET_FORWARD_SECRECY_DATA_2026"
            secret_file.write_bytes(secret_bytes)

            ok, msg = alice.send_file("BobFS", str(secret_file), timeout=5.0)
            proxy_thread.join(timeout=3.0)
            proxy_sock.close()
            server.session_mgr.get_session("BobFS").p2p_port = bob.p2p_port

            assert ok is True, msg
            assert (
                tmp_path / "downloads" / "forward_secret.txt"
            ).read_bytes() == secret_bytes

            # 1. PEER_HELLO & PEER_HELLO_ACK mã hóa bằng khóa chung và chứa x25519_pub
            app_key = get_shared_app_key()
            hello_pkt = captured_c2s[0]
            hello_ack_pkt = captured_s2c[0]
            assert (
                hello_pkt.msg_type == MessageType.PEER_HELLO and hello_pkt.is_encrypted
            )
            assert (
                hello_ack_pkt.msg_type == MessageType.PEER_HELLO_ACK
                and hello_ack_pkt.is_encrypted
            )
            assert "x25519_pub" in hello_pkt.get_decrypted_packet(app_key).to_json()
            assert "x25519_pub" in hello_ack_pkt.get_decrypted_packet(app_key).to_json()

            # 2. FILE_OFFER_REQ, FILE_CHUNK, FILE_ACK phải dùng khóa tạm X25519:
            # Ngay cả khóa AES chung của hệ thống cũng KHÔNG giải mã được!
            offer_pkt = next(
                p for p in captured_c2s if p.msg_type == MessageType.FILE_OFFER_REQ
            )
            chunk_pkt = next(
                p for p in captured_c2s if p.msg_type == MessageType.FILE_CHUNK
            )
            ack_pkt = next(
                p for p in captured_s2c if p.msg_type == MessageType.FILE_ACK
            )

            for ephemeral_pkt in (offer_pkt, chunk_pkt, ack_pkt):
                assert ephemeral_pkt.is_encrypted is True
                with pytest.raises(InvalidToken):
                    ephemeral_pkt.get_decrypted_packet(app_key)
            assert secret_bytes not in chunk_pkt.payload
        finally:
            alice.disconnect()
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_p2p_plaintext_downgrade_rejected(self):
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        try:
            assert bob.connect() and bob.authenticate("BobP2PGuard")[0]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
                raw_sock.settimeout(3.0)
                raw_sock.connect(("127.0.0.1", bob.p2p_port))
                raw_sock.sendall(
                    create_packet(
                        MessageType.PEER_HELLO,
                        {"sender": "Rogue", "protocol_version": PROTOCOL_VERSION},
                    )
                )
                with pytest.raises(ConnectionClosedError):
                    recv_packet(raw_sock)
        finally:
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)
