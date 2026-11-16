"""
Unit & Integration Tests cho Giai đoạn 4: Xác thực & Quản lý Trạng thái Người dùng (Auth & State Management)
Kiểm tra toàn diện:
  1. Kiểm tra tính hợp lệ của Username (độ dài, ký tự đặc biệt).
  2. Quản lý phiên SessionManager (đăng ký, từ chối trùng tên hoa/thường, hủy phiên).
  3. Quy trình xác thực Client-Server (AUTH_REQ -> AUTH_RESP_SUCCESS / AUTH_RESP_FAIL).
  4. Lấy danh bạ người dùng trực tuyến (USER_LIST_REQ -> USER_LIST_RESP).
  5. Phát thanh thông báo trạng thái người dùng (USER_STATUS_BROADCAST: JOINED / LEFT).
"""

import socket
import threading
import time
import pytest

from common.message_types import MessageType
from server.server_core import ServerCore
from server.session_manager import SessionManager
from client.client_core import ClientCore


def get_free_port() -> int:
    """Lấy cổng mạng ngẫu nhiên còn rảnh trên localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestSessionManagerUnit:
    """Kiểm thử đơn vị lớp SessionManager."""

    def test_validate_username(self):
        """Kiểm tra các quy tắc kiểm tra Username hợp lệ và không hợp lệ."""
        # Hợp lệ
        valid_names = ["alice", "Bob_99", "user-name", "Admin123", "a_b-c"]
        for name in valid_names:
            is_valid, reason = SessionManager.validate_username(name)
            assert is_valid is True, f"Kỳ vọng '{name}' hợp lệ nhưng thất bại: {reason}"

        # Không hợp lệ: quá ngắn (< 3)
        assert SessionManager.validate_username("")[0] is False
        assert SessionManager.validate_username("ab")[0] is False

        # Không hợp lệ: quá dài (> 20)
        assert SessionManager.validate_username("a" * 21)[0] is False

        # Không hợp lệ: chứa dấu cách hoặc ký tự đặc biệt
        assert SessionManager.validate_username("user name")[0] is False
        assert SessionManager.validate_username("alice@gmail")[0] is False
        assert SessionManager.validate_username("admin#1")[0] is False

    def test_register_and_unregister(self):
        """Kiểm tra thêm và xóa người dùng khỏi SessionManager."""
        sm = SessionManager()
        dummy_handler = object()

        # Đăng ký lần 1: Thành công
        ok, reason, session = sm.register_user("Alice", dummy_handler, ("127.0.0.1", 10001))
        assert ok is True
        assert session is not None
        assert session.username == "Alice"
        assert sm.get_user_count() == 1
        assert sm.is_online("Alice") is True
        assert sm.is_online("alice") is True  # Không phân biệt hoa thường

        # Đăng ký trùng tên (cùng chữ hoa thường hoặc khác chữ hoa thường): Bị từ chối
        ok_dup, reason_dup, _ = sm.register_user("alice", dummy_handler, ("127.0.0.1", 10002))
        assert ok_dup is False
        assert "đã có người sử dụng" in reason_dup

        # Hủy đăng ký
        removed = sm.unregister_user("Alice")
        assert removed is not None
        assert removed.username == "Alice"
        assert sm.get_user_count() == 0
        assert sm.is_online("Alice") is False

    def test_unregister_by_handler(self):
        """Kiểm tra hủy đăng ký phiên thông qua instance ClientHandler."""
        sm = SessionManager()
        handler1 = object()
        handler2 = object()

        sm.register_user("Bob", handler1, ("127.0.0.1", 10003))
        sm.register_user("Charlie", handler2, ("127.0.0.1", 10004))
        assert sm.get_user_count() == 2

        # Xóa theo handler1
        removed = sm.unregister_by_handler(handler1)
        assert removed is not None
        assert removed.username == "Bob"
        assert sm.get_user_count() == 1
        assert sm.is_online("Bob") is False
        assert sm.is_online("Charlie") is True


class TestAuthenticationIntegration:
    """Kiểm thử tích hợp luồng xác thực Client - Server."""

    def test_client_authentication_success(self):
        """Client kết nối và đăng nhập thành công với username hợp lệ."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        client = ClientCore(server_host="127.0.0.1", server_port=port)
        assert client.connect() is True

        ok, msg = client.authenticate("Alice_01")
        assert ok is True
        assert client.is_authenticated is True
        assert client.username == "Alice_01"
        assert "Alice_01" in client.online_users

        client.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_duplicate_username_rejected(self):
        """Hai client đăng nhập cùng một tên: Client thứ hai bị từ chối."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        c1 = ClientCore(server_host="127.0.0.1", server_port=port)
        c2 = ClientCore(server_host="127.0.0.1", server_port=port)

        assert c1.connect() is True
        assert c2.connect() is True

        # Client 1 đăng nhập "SuperUser" -> Thành công
        ok1, _ = c1.authenticate("SuperUser")
        assert ok1 is True
        assert c1.is_authenticated is True

        # Client 2 đăng nhập "superuser" (trùng tên khác hoa thường) -> Bị từ chối
        ok2, msg2 = c2.authenticate("superuser")
        assert ok2 is False
        assert c2.is_authenticated is False
        assert "đã có người sử dụng" in msg2

        # Client 2 đổi sang tên "OtherUser" -> Thành công
        ok3, _ = c2.authenticate("OtherUser")
        assert ok3 is True
        assert c2.is_authenticated is True

        c1.disconnect()
        c2.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_invalid_username_rejected(self):
        """Client đăng nhập với username không đúng chuẩn: Bị từ chối."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        client = ClientCore(server_host="127.0.0.1", server_port=port)
        assert client.connect() is True

        # Tên chứa dấu cách
        ok, msg = client.authenticate("hello world")
        assert ok is False
        assert client.is_authenticated is False
        assert "chỉ được chứa" in msg or "hợp lệ" in msg

        client.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_user_status_broadcast_and_user_list(self):
        """Kiểm tra Client nhận thông báo JOINED / LEFT và truy vấn danh sách online."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)

        assert alice.connect() is True
        assert alice.authenticate("Alice")[0] is True

        # Alice lắng nghe sự kiện phát thanh trạng thái
        alice_events = []
        alice.register_callback(
            MessageType.USER_STATUS_BROADCAST,
            lambda pkt: alice_events.append(pkt.to_json()),
        )

        # Bob kết nối và đăng nhập
        assert bob.connect() is True
        assert bob.authenticate("Bob")[0] is True

        # Chờ gói tin phát thanh lan truyền tới Alice
        time.sleep(0.4)

        # Alice phải nhận được thông báo Bob JOINED kèm danh sách online & P2P endpoint
        assert len(alice_events) >= 1
        assert alice_events[-1]["event"] == "JOINED"
        assert alice_events[-1]["username"] == "Bob"
        assert set(alice_events[-1]["online_users"]) == {"Alice", "Bob"}
        assert "Bob" in alice_events[-1].get("peers", {})
        assert alice_events[-1].get("peer", {}).get("p2p_port") == bob.p2p_port
        assert "Bob" in alice.online_users
        assert "Bob" in alice.peer_directory

        # Alice chủ động truy vấn danh sách người dùng online
        current_users = alice.request_user_list()
        assert current_users is not None
        assert "Alice" in current_users
        assert "Bob" in current_users

        # Bob ngắt kết nối
        bob.disconnect()
        time.sleep(0.4)

        # Alice phải nhận được thông báo Bob LEFT kèm danh sách online đã loại bỏ Bob
        assert alice_events[-1]["event"] == "LEFT"
        assert alice_events[-1]["username"] == "Bob"
        assert alice_events[-1]["online_users"] == ["Alice"]
        assert "Bob" not in alice_events[-1].get("peers", {})
        assert "Bob" not in alice.online_users
        assert "Bob" not in alice.peer_directory

        alice.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_concurrent_same_username_race_condition(self):
        """Khi 5 luồng cùng gửi yêu cầu đăng ký 1 tên 'RaceWinner' tại cùng 1 thời điểm, chỉ duy nhất 1 luồng thành công."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        num_racers = 5
        clients = [ClientCore(server_host="127.0.0.1", server_port=port) for _ in range(num_racers)]
        barrier = threading.Barrier(num_racers)
        outcomes = [False] * num_racers

        try:
            for c in clients:
                assert c.connect() is True

            def racer(idx: int):
                barrier.wait(timeout=3.0)
                ok, _ = clients[idx].authenticate("RaceWinner", timeout=3.0)
                outcomes[idx] = ok

            threads = [threading.Thread(target=racer, args=(i,)) for i in range(num_racers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5.0)

            # Phải có đúng 1 client đăng nhập thành công và 4 client bị từ chối
            assert outcomes.count(True) == 1
            assert outcomes.count(False) == num_racers - 1
            assert server.session_mgr.get_user_count() == 1
        finally:
            for c in clients:
                c.disconnect()
            server.stop()
            sthread.join(timeout=2.0)

