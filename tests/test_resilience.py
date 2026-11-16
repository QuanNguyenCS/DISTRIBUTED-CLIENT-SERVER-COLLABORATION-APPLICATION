"""
Unit & Integration Tests cho Giai đoạn 7: Khả năng Chịu lỗi, Heartbeat & Dọn dẹp Zombie (Network Resilience)
Kiểm tra toàn diện:
  1. Heartbeat duy trì kết nối sống (Liveness): Client định kỳ gửi PING giúp kết nối không bị timeout.
  2. Dọn dẹp kết nối Zombie (Half-Open Sockets): Khi client ngừng gửi gói tin quá hạn,
     Server ZombieCleanerThread tự động phát hiện, đóng socket và gỡ bỏ phiên.
  3. Xử lý ngắt kết nối an toàn (Graceful Disconnect): Báo tin tức thì cho các client còn lại.
"""

import socket
import threading
import time
import pytest

from common.message_types import MessageType
from server.server_core import ServerCore
from client.client_core import ClientCore


def get_free_port() -> int:
    """Lấy cổng mạng rảnh trên localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestNetworkResilience:
    """Bộ kiểm thử khả năng chịu lỗi và giám sát kết nối mạng."""

    def test_heartbeat_keeps_connection_alive(self):
        """Client bật heartbeat định kỳ giúp Server không coi kết nối là Zombie."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        # Cấu hình timeout ngắn để kiểm thử nhanh
        server.zombie_timeout = 2.0
        server.zombie_check_interval = 0.5
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        client = ClientCore(server_host="127.0.0.1", server_port=port)
        client.heartbeat_interval = 0.6  # Gửi PING mỗi 0.6 giây (nhỏ hơn zombie_timeout 2.0s)

        assert client.connect(start_heartbeat=True) is True
        assert client.authenticate("LiveClient")[0] is True

        # Duy trì kết nối trong 3 giây (lớn hơn zombie_timeout 2.0s)
        time.sleep(3.0)

        # Do có heartbeat ping liên tục, client vẫn phải còn online trên server
        assert server.session_mgr.is_online("LiveClient") is True
        assert client.is_connected is True

        client.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_zombie_cleaner_detects_dead_client(self):
        """Client bị treo/đứt mạng ngầm (không gửi heartbeat): Server tự động dọn dẹp sau timeout."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        server.zombie_timeout = 1.0
        server.zombie_check_interval = 0.3
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        client = ClientCore(server_host="127.0.0.1", server_port=port)
        observer = ClientCore(server_host="127.0.0.1", server_port=port)
        observer.heartbeat_interval = 0.3

        # Observer bật heartbeat để sống, còn ZombieClient tắt heartbeat để mô phỏng đứt mạng ngầm
        assert observer.connect(start_heartbeat=True) is True
        assert observer.authenticate("ObserverPeer")[0] is True

        left_events = []
        left_event_signal = threading.Event()

        def on_status(pkt):
            data = pkt.to_json()
            if data.get("event") == "LEFT" and data.get("username") == "ZombieClient":
                left_events.append(data)
                left_event_signal.set()

        observer.register_callback(MessageType.USER_STATUS_BROADCAST, on_status)

        assert client.connect(start_heartbeat=False) is True
        assert client.authenticate("ZombieClient")[0] is True
        assert server.session_mgr.is_online("ZombieClient") is True

        # Chờ ZombieCleaner quét và phát thông báo LEFT cho ObserverPeer
        assert left_event_signal.wait(timeout=2.5) is True

        # ZombieCleanerThread phải tự động đóng socket, xóa khỏi danh sách online và gửi danh sách mới cho các peer còn lại
        assert server.session_mgr.is_online("ZombieClient") is False
        assert server.get_active_client_count() == 1
        assert len(left_events) == 1
        assert left_events[0]["online_users"] == ["ObserverPeer"]
        assert "ZombieClient" not in left_events[0].get("peers", {})
        assert observer.online_users == ["ObserverPeer"]
        assert "ZombieClient" not in observer.peer_directory

        observer.disconnect()
        client.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_graceful_disconnect_notifies_peers_instantly(self):
        """Khi client chủ động thoát, Server và các peer nhận thông báo tức thì."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)

        assert alice.connect() and alice.authenticate("AlicePeer")[0]
        assert bob.connect() and bob.authenticate("BobPeer")[0]

        alice_notices = []
        alice.register_callback(
            MessageType.USER_STATUS_BROADCAST,
            lambda pkt: alice_notices.append(pkt.to_json()),
        )

        # Bob chủ động thoát
        bob.disconnect()
        time.sleep(0.4)

        # Alice phải nhận được thông báo Bob rời đi ngay
        assert len(alice_notices) >= 1
        assert alice_notices[-1]["event"] == "LEFT"
        assert alice_notices[-1]["username"] == "BobPeer"

        alice.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_received_queue_disabled_by_default_and_disconnect_resets_state(self):
        """F10 & F12: received_queue không tích lũy RAM mặc định; khi Server sập client dọn sạch state & đánh thức waiter."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        disc_event = threading.Event()
        disc_reasons = []
        alice.on_disconnected = lambda r: (disc_reasons.append(r), disc_event.set())

        try:
            assert alice.connect() and alice.authenticate("AliceReset")[0]
            alice.send_broadcast("Msg 1")
            alice.send_broadcast("Msg 2")
            time.sleep(0.2)
            # F10: Mặc định callbacks đã chạy mà received_queue không phình bộ nhớ
            assert alice.received_queue.qsize() == 0

            # F12: Tắt Server đột ngột -> Client tự động reset trạng thái sạch sẽ và kích hoạt on_disconnected
            server.stop()
            sthread.join(timeout=2.0)
            assert disc_event.wait(timeout=2.0) is True
            assert len(disc_reasons) == 1
            assert alice.is_connected is False
            assert alice.is_authenticated is False
            assert alice.username is None
            assert alice.online_users == []
            assert alice.p2p_port is None
        finally:
            alice.disconnect()
            server.stop()
