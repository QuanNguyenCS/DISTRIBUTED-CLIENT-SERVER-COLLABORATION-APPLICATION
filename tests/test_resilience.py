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

        # Tắt heartbeat để mô phỏng client bị đóng băng hoặc ngắt card mạng ngầm
        assert client.connect(start_heartbeat=False) is True
        assert client.authenticate("ZombieClient")[0] is True
        assert server.session_mgr.is_online("ZombieClient") is True

        # Chờ 2 giây (vượt quá zombie_timeout 1.0s)
        time.sleep(2.0)

        # ZombieCleanerThread phải tự động đóng socket và xóa khỏi danh sách online
        assert server.session_mgr.is_online("ZombieClient") is False
        assert server.get_active_client_count() == 0

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
