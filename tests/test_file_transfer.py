"""
Unit & Integration Tests cho Giai đoạn 6: Truyền File Tin Cậy qua TCP (Reliable File Transfer)
Kiểm tra toàn diện:
  1. Đóng gói & giải gói Chunk nhị phân (pack/unpack chunk payload).
  2. Tính toán mã băm SHA-256 đối chiếu tính toàn vẹn.
  3. Ghép file từ các chunk tuần tự (Assembly) và xác thực hash.
  4. Kiểm thử truyền file hoàn chỉnh qua TCP giữa 2 Client (Alice -> Bob).
  5. Xử lý lỗi khi gửi file cho người dùng offline hoặc file không tồn tại.
"""

import os
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path
import pytest

from common.crypto_utils import (
    derive_p2p_session_key,
    generate_ephemeral_x25519_keypair,
    get_shared_app_key,
)
from common.message_types import MessageType
from common.protocol import PROTOCOL_VERSION, create_packet, recv_packet
from server.server_core import ServerCore
from client.client_core import ClientCore
from client.file_transfer import (
    IncomingFileTransfer,
    calculate_file_hash,
    pack_chunk_payload,
    read_file_chunks,
    unpack_chunk_payload,
)


def get_free_port() -> int:
    """Lấy cổng mạng rảnh trên localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def open_encrypted_p2p_session(port: int, sender_name: str):
    """Mở socket P2P, thực hiện PEER_HELLO/ACK mã hóa khóa chung + trao đổi X25519 lấy khóa phiên tạm."""
    app_key = get_shared_app_key()
    priv_key, pub_b64 = generate_ephemeral_x25519_keypair()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect(("127.0.0.1", port))
    sock.sendall(
        create_packet(
            MessageType.PEER_HELLO,
            {"sender": sender_name, "protocol_version": PROTOCOL_VERSION, "x25519_pub": pub_b64},
            encrypt_key=app_key,
        )
    )
    ack = recv_packet(sock, decrypt_key=app_key).to_json()
    assert ack["status"] == "OK"
    session_key = derive_p2p_session_key(priv_key, ack["x25519_pub"])
    return sock, session_key


class TestFileTransferUnit:
    """Kiểm thử đơn vị cho các hàm xử lý file."""

    def test_chunk_pack_and_unpack(self):
        """Kiểm tra đóng gói và mở gói dữ liệu nhị phân của chunk."""
        sample_data = b"HELLO_RAW_BINARY_CHUNK_DATA_12345" * 100
        packed = pack_chunk_payload(
            file_id="test-file-01",
            chunk_index=3,
            total_chunks=10,
            chunk_data=sample_data,
        )

        meta, unpacked_data = unpack_chunk_payload(packed)
        assert meta["file_id"] == "test-file-01"
        assert meta["chunk_index"] == 3
        assert meta["total_chunks"] == 10
        assert meta["chunk_size"] == len(sample_data)
        assert unpacked_data == sample_data

    def test_file_hash_and_chunk_generator(self):
        """Kiểm tra tính mã băm SHA-256 và đọc file theo chunk generator."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"ABCDEFGHIJ" * 10000)  # 100 KB
            temp_path = tf.name

        try:
            expected_hash = calculate_file_hash(temp_path)
            assert len(expected_hash) == 64

            # Đọc chunks với chunk_size = 32 KB
            chunks = list(read_file_chunks(temp_path, chunk_size=32 * 1024))
            assert len(chunks) == 4  # 100KB / 32KB = 3 chunk 32KB + 1 chunk 4KB

            # Ráp lại để so sánh
            rebuilt_data = b"".join(chunk_data for _, chunk_data in chunks)
            assert len(rebuilt_data) == 100000
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


class TestFileTransferIntegration:
    """Kiểm thử truyền file tích hợp qua mạng TCP."""

    def test_full_file_transfer_between_clients(self):
        """Alice gửi file nhị phân (ảnh/tài liệu) trực tiếp P2P cho Bob (Server chỉ làm Tracker)."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        # Tạo thư mục download riêng cho test
        test_dir = tempfile.mkdtemp(prefix="collab_test_")
        alice_file = os.path.join(test_dir, "document.pdf")
        original_content = os.urandom(120 * 1024)  # 120 KB dữ liệu ngẫu nhiên

        with open(alice_file, "wb") as f:
            f.write(original_content)
        original_hash = calculate_file_hash(alice_file)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = os.path.join(test_dir, "bob_downloads")

        assert alice.connect() and alice.authenticate("Alice")[0]
        assert bob.connect() and bob.authenticate("Bob")[0]

        progress_records = []

        def on_progress(sent, total, pct):
            progress_records.append((sent, total, pct))

        # Alice gửi file cho Bob
        success, msg = alice.send_file(
            recipient="Bob",
            file_path=alice_file,
            progress_callback=on_progress,
            timeout=10.0,
        )

        assert success is True
        assert "toàn vẹn 100%" in msg
        assert len(progress_records) > 0
        assert progress_records[-1][2] == 100.0  # Tiến độ đạt 100%

        # Kiểm tra file đã lưu tại thư mục download của Bob
        bob_received_file = os.path.join(bob.download_dir, "document.pdf")
        assert os.path.isfile(bob_received_file)

        # Đối chiếu mã băm và nội dung file bit-by-bit
        received_hash = calculate_file_hash(bob_received_file)
        assert received_hash == original_hash

        with open(bob_received_file, "rb") as f:
            assert f.read() == original_content

        # Dọn dẹp
        alice.disconnect()
        bob.disconnect()
        server.stop()
        sthread.join(timeout=2.0)
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_send_file_to_offline_user_fails(self):
        """Alice gửi file cho người dùng không online: Báo lỗi phù hợp."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"Test content")
            test_file = tf.name

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        assert alice.connect() and alice.authenticate("AliceSender")[0]

        success, reason = alice.send_file(
            recipient="GhostReceiver",
            file_path=test_file,
            timeout=2.0,
        )

        assert success is False
        assert "không online" in reason or "hết thời gian" in reason

        alice.disconnect()
        server.stop()
        sthread.join(timeout=2.0)
        if os.path.exists(test_file):
            os.remove(test_file)

    def test_tracker_lookup_and_server_rejects_file_relay(self, tmp_path):
        """Server Tracker cung cấp IP:P2P_Port và từ chối mọi gói FILE_* đi qua Server relay."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        assert not hasattr(server.router, "route_file_offer")
        assert not hasattr(server.router, "route_file_chunk")

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = str(tmp_path / "downloads")

        try:
            assert alice.connect() and alice.authenticate("AliceLookup")[0]
            assert bob.connect() and bob.authenticate("BobLookup")[0]
            assert bob.p2p_port is not None and bob.p2p_port > 0

            # Lookup qua Tracker trả về đúng địa chỉ (ip, p2p_port) của Bob
            found, endpoint, msg = alice.lookup_peer("BobLookup")
            assert found is True, msg
            assert endpoint == ("127.0.0.1", bob.p2p_port)

            # Lookup người dùng không online trả found=False
            found_ghost, ep_ghost, reason_ghost = alice.lookup_peer("OfflineUser")
            assert found_ghost is False
            assert ep_ghost is None
            assert "không online" in reason_ghost

            # Gửi thẳng FILE_OFFER_REQ / FILE_CHUNK lên Server phải bị từ chối bằng FILE_P2P_ONLY
            err_notices = []
            err_event = threading.Event()
            alice.register_callback(
                MessageType.ERROR_NOTICE,
                lambda pkt: (err_notices.append(pkt.to_json()), err_event.set()),
            )
            assert alice.send_packet(
                MessageType.FILE_OFFER_REQ,
                {"file_id": "bad1", "sender": "AliceLookup", "recipient": "BobLookup"},
            )
            assert err_event.wait(timeout=2.0)
            assert err_notices[-1]["code"] == "FILE_P2P_ONLY"
        finally:
            alice.disconnect()
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_p2p_unreachable_port_fails_without_server_fallback(self, tmp_path):
        """Khi cổng P2P bị chặn/không thể kết nối, send_file báo lỗi P2P ngay lập tức, không fallback Server."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = str(tmp_path / "downloads")

        try:
            assert alice.connect() and alice.authenticate("AliceBlocked")[0]
            assert bob.connect() and bob.authenticate("BobBlocked")[0]

            # Giả lập tường lửa chặn cổng P2P bằng cách đóng Listener P2P của Bob
            bob.stop_p2p_listener()

            src_file = tmp_path / "blocked.bin"
            src_file.write_bytes(b"CannotRelayThroughServer" * 10)

            ok, reason = alice.send_file("BobBlocked", str(src_file), timeout=3.0)
            assert ok is False
            assert "Không thể kết nối P2P" in reason
            assert not (tmp_path / "downloads" / "blocked.bin").exists()
        finally:
            alice.disconnect()
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_p2p_lookup_fails_when_peer_has_no_p2p_port(self, tmp_path):
        """Peer kết nối nhưng không công bố cổng P2P (start_p2p=False): Tracker báo lỗi rõ ràng."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        no_p2p = ClientCore(server_host="127.0.0.1", server_port=port)

        try:
            assert alice.connect() and alice.authenticate("AliceP2P")[0]
            assert no_p2p.connect(start_p2p=False) and no_p2p.authenticate("NoP2P")[0]
            assert no_p2p.p2p_port is None

            src_file = tmp_path / "nop2p.txt"
            src_file.write_text("hello", encoding="utf-8")

            ok, reason = alice.send_file("NoP2P", str(src_file), timeout=3.0)
            assert ok is False
            assert "cổng nhận file P2P" in reason
        finally:
            alice.disconnect()
            no_p2p.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_corrupted_chunk_sha256_mismatch_rejected_and_cleaned_up(self, tmp_path):
        """Khi dữ liệu chunk bị hỏng trên đường truyền (sai SHA-256), bên nhận phải từ chối và xóa sạch file lỗi."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = str(tmp_path / "bob_downloads")
        bob_errors = []
        bob_err_event = threading.Event()
        bob.on_file_error = lambda s, f, r: (bob_errors.append((s, f, r)), bob_err_event.set())

        try:
            assert bob.connect() and bob.authenticate("BobReceiver")[0]
            assert bob.p2p_port is not None

            # Mở kết nối P2P có bắt tay X25519 rồi cố tình gửi dữ liệu lật bit khác SHA-256 đã khai báo
            p2p_sock, session_key = open_encrypted_p2p_session(bob.p2p_port, "EvilAlice")
            with p2p_sock:
                # Khai báo SHA-256 giả (64 ký tự '0') không khớp với dữ liệu thực
                p2p_sock.sendall(
                    create_packet(
                        MessageType.FILE_OFFER_REQ,
                        {
                            "file_id": "badsha01",
                            "sender": "EvilAlice",
                            "recipient": "BobReceiver",
                            "file_name": "corrupted.bin",
                            "file_size": 16,
                            "total_chunks": 1,
                            "sha256": "0" * 64,
                        },
                        encrypt_key=session_key,
                    )
                )
                offer_resp = recv_packet(p2p_sock, decrypt_key=session_key).to_json()
                assert offer_resp["status"] == "ACCEPTED"

                bad_chunk = pack_chunk_payload("badsha01", 0, 1, b"CORRUPTED_DATA!!", encrypted=True)
                p2p_sock.sendall(create_packet(MessageType.FILE_CHUNK, bad_chunk, encrypt_key=session_key))

                ack_pkt = recv_packet(p2p_sock, decrypt_key=session_key)
                assert ack_pkt.msg_type == MessageType.FILE_ACK
                ack_data = ack_pkt.to_json()
                assert ack_data["status"] == "FAILED"
                assert "SHA-256" in ack_data["reason"]

            assert bob_err_event.wait(timeout=2.0)
            assert len(bob_errors) == 1
            # Đảm bảo KHÔNG có file hỏng hoặc file .part nào bị bỏ sót trên ổ đĩa của Bob
            assert not (tmp_path / "bob_downloads" / "corrupted.bin").exists()
            leftover_files = list((tmp_path / "bob_downloads").glob("*")) if (tmp_path / "bob_downloads").exists() else []
            assert leftover_files == []
        finally:
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_p2p_path_traversal_filename_sanitized(self, tmp_path):
        """Kiểm tra chống lỗ hổng Path Traversal: tên file chứa '../' hoặc '..\\' phải được lọc sạch về thư mục download."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        dl_dir = tmp_path / "safe_downloads"
        bob.download_dir = str(dl_dir)

        try:
            assert bob.connect() and bob.authenticate("BobSafe")[0]
            payload_bytes = b"SafeContentInsideDownloadDirOnly"
            import hashlib
            valid_sha = hashlib.sha256(payload_bytes).hexdigest()

            for idx, malicious_name in enumerate(["../../escaped_unix.txt", "..\\..\\escaped_win.txt"]):
                p2p_sock, session_key = open_encrypted_p2p_session(bob.p2p_port, "Sender")
                with p2p_sock:
                    fid = f"trav0{idx}"
                    p2p_sock.sendall(
                        create_packet(
                            MessageType.FILE_OFFER_REQ,
                            {
                                "file_id": fid,
                                "sender": "Sender",
                                "recipient": "BobSafe",
                                "file_name": malicious_name,
                                "file_size": len(payload_bytes),
                                "total_chunks": 1,
                                "sha256": valid_sha,
                            },
                            encrypt_key=session_key,
                        )
                    )
                    assert recv_packet(p2p_sock, decrypt_key=session_key).to_json()["status"] == "ACCEPTED"
                    p2p_sock.sendall(
                        create_packet(MessageType.FILE_CHUNK, pack_chunk_payload(fid, 0, 1, payload_bytes, encrypted=True), encrypt_key=session_key)
                    )
                    ack = recv_packet(p2p_sock, decrypt_key=session_key).to_json()
                    assert ack["status"] == "SUCCESS"

            # File phải nằm gọn bên trong safe_downloads, tuyệt đối không thoát ra tmp_path
            assert (dl_dir / "escaped_unix.txt").is_file()
            assert (dl_dir / "escaped_win.txt").is_file()
            assert not (tmp_path / "escaped_unix.txt").exists()
            assert not (tmp_path / "escaped_win.txt").exists()
        finally:
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_concurrent_p2p_file_transfers_to_same_receiver(self, tmp_path):
        """Hai client (Alice và Charlie) đồng thời truyền 2 file P2P tới cùng Bob một lúc."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        charlie = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = str(tmp_path / "bob_concurrent")

        try:
            assert alice.connect() and alice.authenticate("AliceP2P1")[0]
            assert charlie.connect() and charlie.authenticate("CharlieP2P2")[0]
            assert bob.connect() and bob.authenticate("BobTarget")[0]

            file_a = tmp_path / "alice_data.bin"
            file_c = tmp_path / "charlie_data.bin"
            bytes_a = os.urandom(96 * 1024)  # 3 chunks
            bytes_c = os.urandom(96 * 1024)  # 3 chunks
            file_a.write_bytes(bytes_a)
            file_c.write_bytes(bytes_c)

            results = {}

            def send_worker(client_obj, key, path):
                results[key] = client_obj.send_file("BobTarget", str(path), timeout=10.0)

            t1 = threading.Thread(target=send_worker, args=(alice, "A", file_a))
            t2 = threading.Thread(target=send_worker, args=(charlie, "C", file_c))
            t1.start()
            t2.start()
            t1.join(timeout=10.0)
            t2.join(timeout=10.0)

            assert results["A"][0] is True, results["A"][1]
            assert results["C"][0] is True, results["C"][1]
            assert (tmp_path / "bob_concurrent" / "alice_data.bin").read_bytes() == bytes_a
            assert (tmp_path / "bob_concurrent" / "charlie_data.bin").read_bytes() == bytes_c
        finally:
            alice.disconnect()
            charlie.disconnect()
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_duplicate_good_filename_not_overwritten(self, tmp_path):
        """F8: File tốt có sẵn trong thư mục tải về tuyệt đối không bị ghi đè khi nhận file trùng tên."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        dl_dir = tmp_path / "downloads"
        dl_dir.mkdir(parents=True, exist_ok=True)
        existing_good = dl_dir / "report.txt"
        existing_good.write_bytes(b"ORIGINAL_VALUABLE_DATA")
        bob.download_dir = str(dl_dir)

        try:
            assert alice.connect() and alice.authenticate("AliceDup")[0]
            assert bob.connect() and bob.authenticate("BobDup")[0]

            new_src = tmp_path / "report.txt"
            new_src.write_bytes(b"SECOND_FILE_CONTENT")

            ok, msg = alice.send_file("BobDup", str(new_src), timeout=5.0)
            assert ok is True, msg
            assert existing_good.read_bytes() == b"ORIGINAL_VALUABLE_DATA"
            renamed = dl_dir / "report (1).txt"
            assert renamed.is_file()
            assert renamed.read_bytes() == b"SECOND_FILE_CONTENT"
        finally:
            alice.disconnect()
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

    def test_malformed_chunk_index_or_size_rejected_and_cleaned(self, tmp_path):
        """F9: Gửi chunk sai chỉ số [0, total_chunks) hoặc vượt file_size phải bị từ chối và xóa sạch file .part."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        dl_dir = tmp_path / "bob_clean"
        bob.download_dir = str(dl_dir)

        try:
            assert bob.connect() and bob.authenticate("BobStrict")[0]
            p2p_sock, session_key = open_encrypted_p2p_session(bob.p2p_port, "Sender")
            with p2p_sock:
                p2p_sock.sendall(
                    create_packet(
                        MessageType.FILE_OFFER_REQ,
                        {
                            "file_id": "badidx01",
                            "sender": "Sender",
                            "recipient": "BobStrict",
                            "file_name": "test.bin",
                            "file_size": 10,
                            "total_chunks": 1,
                            "sha256": "a" * 64,
                        },
                        encrypt_key=session_key,
                    )
                )
                assert recv_packet(p2p_sock, decrypt_key=session_key).to_json()["status"] == "ACCEPTED"

                # Cố tình gửi chunk_index = 5 khi total_chunks = 1
                bad_chunk = pack_chunk_payload("badidx01", 5, 1, b"1234567890", encrypted=True)
                p2p_sock.sendall(create_packet(MessageType.FILE_CHUNK, bad_chunk, encrypt_key=session_key))

                ack = recv_packet(p2p_sock, decrypt_key=session_key).to_json()
                assert ack["status"] == "FAILED"

            leftovers = list(dl_dir.glob("*")) if dl_dir.exists() else []
            assert leftovers == []
        finally:
            bob.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

