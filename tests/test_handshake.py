"""
Unit & Integration Tests cho Giai đoạn 2: Cơ chế Bắt tay TCP Client-Server
Kiểm tra toàn diện:
  1. Bắt tay thành công giữa Client và Server (HELLO_HANDSHAKE -> HANDSHAKE_ACK)
  2. Bắt tay bị từ chối khi sai phiên bản giao thức (HANDSHAKE_REJECT)
  3. Xử lý lỗi khi Server không hoạt động (ConnectionRefusedError)
  4. Cơ chế ngắt kết nối lịch sự (DISCONNECT_NOTICE)
  5. Khởi động và dừng Server an toàn
"""

import socket
import threading
import time
import pytest

from common.message_types import MessageType
from common.protocol import (
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    create_packet,
    recv_packet,
)
from server.server_core import ServerCore
from client.client_core import ClientCore


def get_free_port() -> int:
    """Tìm một cổng mạng còn trống trên localhost để tránh xung đột cổng khi test."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestClientServerHandshake:
    """Bộ kiểm thử cho quy trình bắt tay TCP và Handshake ứng dụng."""

    def test_successful_handshake(self):
        """Kiểm tra quá trình bắt tay chuẩn: Client kết nối -> Bắt tay thành công -> Ngắt kết nối."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port, server_id="TestServer-01")
        server.start()

        server_thread_result = {}

        def server_worker():
            client_sock, client_addr = server.accept_one()
            server_thread_result["client_sock"] = client_sock
            server_thread_result["client_addr"] = client_addr
            if client_sock:
                # Đọc DISCONNECT_NOTICE khi client ngắt kết nối
                try:
                    pkt = recv_packet(client_sock)
                    server_thread_result["disconnect_pkt"] = pkt
                except Exception:
                    pass
                finally:
                    client_sock.close()

        sthread = threading.Thread(target=server_worker, daemon=True)
        sthread.start()

        # Client kết nối
        client = ClientCore(server_host="127.0.0.1", server_port=port, client_name="TesterClient")
        connected = client.connect(timeout=3.0)

        assert connected is True
        assert client.is_connected is True
        assert client.server_info is not None
        assert client.server_info["status"] == "OK"
        assert client.server_info["server_id"] == "TestServer-01"
        assert client.server_info["version"] == PROTOCOL_VERSION

        # Chờ socket TCP ổn định rồi ngắt kết nối
        time.sleep(0.05)
        client.disconnect()
        sthread.join(timeout=2.0)
        server.stop()

        assert server_thread_result.get("client_sock") is not None
        assert server_thread_result.get("disconnect_pkt") is not None
        assert server_thread_result["disconnect_pkt"].msg_type == MessageType.DISCONNECT_NOTICE

    def test_handshake_rejected_on_version_mismatch(self):
        """Kiểm tra Server từ chối bắt tay khi Client gửi phiên bản không tương thích."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port, server_id="TestServer-01")
        server.start()

        def server_worker():
            client_sock, _ = server.accept_one()
            if client_sock:
                client_sock.close()

        sthread = threading.Thread(target=server_worker, daemon=True)
        sthread.start()

        # Client gửi phiên bản không tương thích (ví dụ: version = 99)
        client = ClientCore(server_host="127.0.0.1", server_port=port, client_name="OutdatedClient")
        connected = client.connect(timeout=3.0, protocol_version=99)

        assert connected is False
        assert client.is_connected is False

        sthread.join(timeout=2.0)
        server.stop()

    def test_connection_refused_when_server_is_down(self):
        """Kiểm tra ngoại lệ khi server không chạy (ConnectionRefusedError hoặc TimeoutError)."""
        unused_port = get_free_port()
        client = ClientCore(server_host="127.0.0.1", server_port=unused_port)

        with pytest.raises((ConnectionRefusedError, TimeoutError, socket.timeout)):
            client.connect(timeout=0.5)

    def test_server_rejects_non_handshake_first_packet(self):
        """Kiểm tra nếu gói tin đầu tiên không phải HELLO_HANDSHAKE thì server từ chối."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        server.start()

        def server_worker():
            server.accept_one()

        sthread = threading.Thread(target=server_worker, daemon=True)
        sthread.start()

        # Tạo raw socket gửi gói CHAT_BROADCAST thay vì HELLO_HANDSHAKE
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.connect(("127.0.0.1", port))
        wrong_packet = create_packet(MessageType.CHAT_BROADCAST, "Xin chao")
        raw_sock.sendall(wrong_packet)

        # Server phải phản hồi HANDSHAKE_REJECT
        resp = recv_packet(raw_sock)
        assert resp.msg_type == MessageType.HANDSHAKE_REJECT
        raw_sock.close()

        sthread.join(timeout=2.0)
        server.stop()

    def test_server_start_and_stop_idempotent(self):
        """Kiểm tra Server có thể start và stop nhiều lần mà không bị lỗi crash."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)

        server.start()
        assert server.is_running is True

        # Gọi start lần nữa không gây lỗi
        server.start()
        assert server.is_running is True

        server.stop()
        assert server.is_running is False

        # Gọi stop lần nữa không gây lỗi
        server.stop()
        assert server.is_running is False

    def test_server_rejects_corrupted_magic_bytes_during_handshake(self):
        """Nếu client kết nối TCP rồi gửi byte rác không đúng chuẩn Magic Bytes, Server tự đóng kết nối an toàn."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        server.start()

        result = {}

        def server_worker():
            sock, addr = server.accept_one()
            result["sock"] = sock
            result["addr"] = addr

        sthread = threading.Thread(target=server_worker, daemon=True)
        sthread.start()

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.connect(("127.0.0.1", port))
        raw_sock.sendall(b"GARBAGE_BYTES_NOT_CA_PROTOCOL_HEADER")
        raw_sock.close()

        sthread.join(timeout=2.0)
        server.stop()
        assert result.get("sock") is None

    def test_hello_non_dict_json_does_not_crash_server(self):
        """F1: HELLO_HANDSHAKE chứa JSON hợp lệ không phải dict ([], null, 123) không làm sập Server."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        try:
            for bad_payload in ([], b"null", b"12345", b"\xff\xfe\xfd"):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
                    raw_sock.settimeout(2.0)
                    raw_sock.connect(("127.0.0.1", port))
                    raw_sock.sendall(create_packet(MessageType.HELLO_HANDSHAKE, bad_payload))
                    resp = recv_packet(raw_sock)
                    assert resp.msg_type == MessageType.HANDSHAKE_REJECT

            # Server vẫn còn sống và phục vụ Client bình thường ngay sau đó
            assert server.is_running is True
            assert sthread.is_alive() is True
            client = ClientCore(server_host="127.0.0.1", server_port=port)
            assert client.connect(timeout=2.0) is True
            client.disconnect()
        finally:
            server.stop()
            sthread.join(timeout=2.0)

    def test_start_on_occupied_port_raises_without_deadlock(self):
        """F2: ServerCore.start() trên cổng đã bị chiếm phải ném OSError ngay, không tự deadlock."""
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        occupied_port = blocker.getsockname()[1]

        outcome = {}
        done = threading.Event()

        def try_start():
            srv = ServerCore(host="127.0.0.1", port=occupied_port)
            try:
                srv.start()
            except OSError as exc:
                outcome["exc"] = exc
            finally:
                done.set()

        try:
            t = threading.Thread(target=try_start, daemon=True)
            t.start()
            assert done.wait(timeout=2.0) is True, "ServerCore.start() bị deadlock khi cổng đã bị chiếm!"
            assert isinstance(outcome.get("exc"), OSError)
        finally:
            blocker.close()

    def test_slow_handshake_does_not_block_next_client(self):
        """F4: Một Client nối TCP rồi im lặng (hoặc gửi nhỏ giọt) không được chặn Client kế tiếp kết nối."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        server.HANDSHAKE_TIMEOUT = 3.0
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        slow_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        good_client = ClientCore(server_host="127.0.0.1", server_port=port)
        try:
            slow_sock.connect(("127.0.0.1", port))
            # Gửi 4 byte lửng rồi im bặt
            slow_sock.sendall(b"CA\x01\x00")

            start_t = time.monotonic()
            assert good_client.connect(timeout=1.5) is True
            assert good_client.authenticate("FastClient", timeout=1.5)[0] is True
            elapsed = time.monotonic() - start_t
            assert elapsed < 1.5
        finally:
            slow_sock.close()
            good_client.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

