"""
Unit & Integration Tests cho Giai đoạn 3: Xử lý Đa nhiệm & Đa kết nối Đồng thời (Concurrency)
Kiểm tra toàn diện:
  1. Mô hình Thread-per-Client: Phục vụ đồng thời nhiều Client cùng lúc (5-10 clients).
  2. Trao đổi thông điệp song song: Client gửi tin nhắn Broadcast, tất cả client khác nhận được.
  3. Khả năng chịu lỗi: 1 Client ngắt kết nối đột ngột không làm ảnh hưởng đến các Client khác.
  4. Quản lý dọn dẹp tài nguyên và tắt Server an toàn đa luồng.
"""

import queue
import socket
import threading
import time
import pytest

from common.message_types import MessageType
from common.protocol import PROTOCOL_VERSION, Packet
from server.server_core import ServerCore
from client.client_core import ClientCore


def get_free_port() -> int:
    """Lấy cổng mạng rảnh trên localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestConcurrencyAndMultiClients:
    """Bộ kiểm thử khả năng xử lý đa luồng đồng thời của hệ thống."""

    def test_multiple_clients_connect_simultaneously(self):
        """Kiểm tra Server xử lý đồng thời 5 clients kết nối cùng lúc mà không bị nghẽn (Non-blocking)."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port, server_id="MultiServer-01")
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        # Đợi một chút để server socket bind và listen sẵn sàng
        time.sleep(0.3)

        num_clients = 5
        clients = [None] * num_clients
        threads = []
        results = [False] * num_clients

        def connect_worker(index: int):
            c = ClientCore(
                server_host="127.0.0.1",
                server_port=port,
                client_name=f"Client_{index}",
            )
            success = c.connect(timeout=3.0)
            results[index] = success
            if success:
                clients[index] = c

        for i in range(num_clients):
            t = threading.Thread(target=connect_worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=3.0)

        active_clients = [c for c in clients if c is not None]
        # Kiểm tra tất cả 5 clients đều kết nối thành công
        assert all(results) is True
        assert len(active_clients) == num_clients

        # Kiểm tra Server ghi nhận đúng số client trực tuyến
        time.sleep(0.3)
        assert server.get_active_client_count() == num_clients

        # Ngắt kết nối tất cả các clients
        for c in active_clients:
            c.disconnect()

        time.sleep(0.3)
        assert server.get_active_client_count() == 0

        server.stop()
        server_thread.join(timeout=2.0)

    def test_concurrent_broadcast_messaging(self):
        """Kiểm tra một client gửi tin nhắn broadcast, các client khác đều nhận được qua Receiver Thread."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.3)

        # Khởi tạo 3 client: Alice, Bob, Charlie
        alice = ClientCore(server_host="127.0.0.1", server_port=port, client_name="Alice")
        bob = ClientCore(server_host="127.0.0.1", server_port=port, client_name="Bob")
        charlie = ClientCore(server_host="127.0.0.1", server_port=port, client_name="Charlie")

        assert alice.connect() is True and alice.authenticate("Alice")[0] is True
        assert bob.connect() is True and bob.authenticate("Bob")[0] is True
        assert charlie.connect() is True and charlie.authenticate("Charlie")[0] is True

        time.sleep(0.2)
        assert server.get_active_client_count() == 3

        # Hàng đợi để hứng tin nhắn của Bob và Charlie
        bob_messages = []
        charlie_messages = []

        bob.register_callback(
            MessageType.CHAT_BROADCAST,
            lambda pkt: bob_messages.append(pkt.to_json()),
        )
        charlie.register_callback(
            MessageType.CHAT_BROADCAST,
            lambda pkt: charlie_messages.append(pkt.to_json()),
        )

        # Alice gửi tin nhắn broadcast
        test_text = "Xin chao tat ca moi nguoi tu Alice!"
        alice.send_chat(test_text)

        # Chờ tối đa 2 giây để gói tin lan truyền qua mạng TCP
        timeout = time.time() + 2.0
        while time.time() < timeout:
            if bob_messages and charlie_messages:
                break
            time.sleep(0.05)

        # Cả Bob và Charlie đều phải nhận được tin nhắn của Alice
        assert len(bob_messages) == 1
        assert bob_messages[0]["sender"] == "Alice"
        assert bob_messages[0]["text"] == test_text

        assert len(charlie_messages) == 1
        assert charlie_messages[0]["sender"] == "Alice"
        assert charlie_messages[0]["text"] == test_text

        # Dọn dẹp
        alice.disconnect()
        bob.disconnect()
        charlie.disconnect()
        server.stop()
        server_thread.join(timeout=2.0)

    def test_abrupt_disconnect_of_one_client_does_not_affect_others(self):
        """Kiểm tra khi 1 client bị rớt mạng đột ngột (không gửi notice), server và các client khác vẫn hoạt động tốt."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.3)

        c1 = ClientCore(server_host="127.0.0.1", server_port=port, client_name="Client1")
        c2 = ClientCore(server_host="127.0.0.1", server_port=port, client_name="Client2")

        assert c1.connect() is True and c1.authenticate("Client1")[0] is True
        assert c2.connect() is True and c2.authenticate("Client2")[0] is True
        time.sleep(0.2)
        assert server.get_active_client_count() == 2

        # C1 ngắt socket đột ngột (ép đóng socket mà không báo notice)
        if c1.sock:
            c1.sock.close()
            c1.sock = None
        c1.is_connected = False

        time.sleep(0.3)

        # C2 vẫn hoạt động bình thường và gửi nhận tin tốt
        c2_received = []
        c2.register_callback(
            MessageType.CHAT_BROADCAST,
            lambda pkt: c2_received.append(pkt.to_json()),
        )

        c2.send_chat("C2 van song sot tot!")
        time.sleep(0.3)

        # C2 nhận được phản hồi broadcast của chính mình từ Server
        assert len(c2_received) == 1
        assert c2_received[0]["text"] == "C2 van song sot tot!"

        c2.disconnect()
        server.stop()
        server_thread.join(timeout=2.0)

    def test_server_stop_cleans_up_all_handlers(self):
        """Kiểm tra Server khi gọi stop() sẽ đóng toàn bộ các client handlers một cách an toàn."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.3)

        clients = [
            ClientCore(server_host="127.0.0.1", server_port=port, client_name=f"User_{i}")
            for i in range(3)
        ]
        for c in clients:
            c.connect()

        time.sleep(0.2)
        assert server.get_active_client_count() == 3

        # Dừng server
        server.stop()
        server_thread.join(timeout=2.0)

        # Server phải dọn sạch handlers
        assert server.get_active_client_count() == 0
        assert server.is_running is False

    def test_simultaneous_burst_without_interleaving_or_loss(self):
        """6 Clients đã xác thực cùng đồng loạt bắn tin nhắn ở cùng 1 mili-giây (Barrier): không đan xen byte, không mất gói."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.3)

        n = 6
        clients = [ClientCore(server_host="127.0.0.1", server_port=port) for _ in range(n)]
        received_counts = [0] * n
        lock = threading.Lock()
        all_done = threading.Event()
        expected_per_client = n  # Mỗi client nhận n tin broadcast

        try:
            for idx, c in enumerate(clients):
                assert c.connect() is True
                assert c.authenticate(f"BurstUser_{idx}")[0] is True

                def make_cb(i: int):
                    def _cb(pkt: Packet):
                        data = pkt.to_json()
                        assert "BurstMsg-" in data["content"]
                        with lock:
                            received_counts[i] += 1
                            if all(cnt >= expected_per_client for cnt in received_counts):
                                all_done.set()
                    return _cb

                c.register_callback(MessageType.CHAT_BROADCAST, make_cb(idx))

            barrier = threading.Barrier(n)

            def burst_sender(idx: int):
                barrier.wait(timeout=3.0)
                assert clients[idx].send_broadcast(f"BurstMsg-from-{idx}") is True

            threads = [threading.Thread(target=burst_sender, args=(i,)) for i in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=3.0)

            assert all_done.wait(timeout=3.0) is True
            assert received_counts == [expected_per_client] * n
        finally:
            for c in clients:
                c.disconnect()
            server.stop()
            server_thread.join(timeout=2.0)

    def test_unauthenticated_client_blocked_from_chat_and_lookup(self):
        """F3: Client mới chỉ connect/handshake (chưa AUTH_REQ) không được phép gửi hoặc nhận CHAT/LOOKUP."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port, client_name="Alice")
        guest = ClientCore(server_host="127.0.0.1", server_port=port, client_name="SpoofedAlice")

        try:
            assert alice.connect() is True and alice.authenticate("Alice")[0] is True
            assert guest.connect() is True  # Cố tình KHÔNG gọi authenticate

            alice_broadcasts = []
            guest_broadcasts = []
            guest_errors = []
            err_event = threading.Event()

            alice.register_callback(MessageType.CHAT_BROADCAST, lambda p: alice_broadcasts.append(p.to_json()))
            guest.register_callback(MessageType.CHAT_BROADCAST, lambda p: guest_broadcasts.append(p.to_json()))
            guest.register_callback(
                MessageType.ERROR_NOTICE,
                lambda p: (guest_errors.append(p.to_json()), err_event.set()),
            )

            # Guest chưa login cố gửi chat -> bị chặn AUTH_REQUIRED
            guest.send_broadcast("Tin nhan gia mao")
            assert err_event.wait(timeout=2.0) is True
            assert guest_errors[-1]["code"] == "AUTH_REQUIRED"

            # Alice gửi chat -> Guest chưa auth không được nhận
            assert alice.send_broadcast("Tin noi bo") is True
            time.sleep(0.3)
            assert len(alice_broadcasts) == 1
            assert alice_broadcasts[0]["content"] == "Tin noi bo"
            assert len(guest_broadcasts) == 0
        finally:
            alice.disconnect()
            guest.disconnect()
            server.stop()
            server_thread.join(timeout=2.0)


