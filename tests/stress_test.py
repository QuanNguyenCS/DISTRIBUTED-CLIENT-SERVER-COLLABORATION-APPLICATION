"""
File: tests/stress_test.py
Mô tả: Script kiểm thử tải cao (Stress Testing & Load Capacity) cho hệ thống phân tán.
Khởi tạo đồng thời 15-20 luồng Headless Bot Client kết nối vào Server, gửi tin nhắn
Broadcast và Unicast liên tục, đo đạc độ trễ và tỷ lệ phân phối tin nhắn thành công.

Cách chạy:
  1. Chạy độc lập: python tests/stress_test.py [--clients 20] [--duration 10]
  2. Chạy qua pytest: pytest tests/stress_test.py
"""

import argparse
import os
import random
import socket
import sys
import threading
import time
from typing import List

# Đảm bảo đường dẫn gốc dự án có trong sys.path khi chạy script độc lập
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.logger import get_logger
from common.message_types import MessageType
from client.client_core import ClientCore
from server.server_core import ServerCore

logger = get_logger("stress_test")


def get_free_port() -> int:
    """Lấy cổng TCP còn rảnh trên máy."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BotClient:
    """Mô phỏng một bot client tự động thực hiện các hành động trò chuyện."""

    def __init__(self, bot_id: int, host: str, port: int) -> None:
        self.bot_id = bot_id
        self.username = f"Bot_{bot_id:02d}"
        self.host = host
        self.port = port
        self.client = ClientCore(server_host=host, server_port=port, client_name=self.username)
        self.messages_sent = 0
        self.broadcast_sent = 0
        self.direct_sent = 0
        self.messages_received = 0
        self.is_active = False

    def start(self) -> bool:
        """Kết nối và đăng nhập vào Server."""
        if not self.client.connect(timeout=5.0):
            return False

        ok, _ = self.client.authenticate(self.username, timeout=5.0)
        if not ok:
            self.client.disconnect()
            return False

        self.client.register_callback(
            MessageType.CHAT_BROADCAST,
            lambda pkt: self._on_msg(),
        )
        self.client.register_callback(
            MessageType.CHAT_DIRECT,
            lambda pkt: self._on_msg(),
        )

        self.is_active = True
        return True

    def _on_msg(self) -> None:
        self.messages_received += 1

    def send_random_chat(self, all_bot_names: List[str]) -> bool:
        """Gửi ngẫu nhiên tin nhắn phòng chung hoặc tin nhắn riêng."""
        if not self.is_active or not self.client.is_connected:
            return False

        is_direct = random.random() < 0.35
        if is_direct and len(all_bot_names) > 1:
            # Chọn ngẫu nhiên bot khác để gửi tin nhắn riêng 1-1
            peers = [b for b in all_bot_names if b != self.username]
            recipient = random.choice(peers)
            content = f"[Direct from {self.username}] Hello @{recipient} #{self.messages_sent + 1}"
            ok = self.client.send_direct_message(recipient, content)
            if ok:
                self.direct_sent += 1
        else:
            # Gửi broadcast phòng chung
            content = f"[Broadcast from {self.username}] Status update #{self.messages_sent + 1}"
            ok = self.client.send_broadcast(content)
            if ok:
                self.broadcast_sent += 1

        if ok:
            self.messages_sent += 1
        return ok

    def stop(self) -> None:
        """Ngắt kết nối bot an toàn."""
        self.is_active = False
        if self.client:
            self.client.disconnect()


def run_stress_test(num_clients: int = 15, duration_seconds: float = 6.0) -> dict:
    """
    Thực thi bài kiểm thử stress test với số lượng client và thời gian chỉ định.
    """
    port = get_free_port()
    server = ServerCore(host="127.0.0.1", port=port, server_id="StressTestServer")

    sthread = threading.Thread(target=server.serve_forever, daemon=True)
    sthread.start()
    time.sleep(0.3)

    bots: List[BotClient] = []
    bot_names = [f"Bot_{i:02d}" for i in range(1, num_clients + 1)]

    print(f"\n🚀 [Stress Test] Bắt đầu khởi tạo {num_clients} Clients kết nối đồng thời tới 127.0.0.1:{port}...")

    # 1. Kết nối đồng loạt các clients
    start_connect_time = time.time()
    connection_threads = []

    def connect_bot(b: BotClient):
        b.start()

    for i in range(1, num_clients + 1):
        bot = BotClient(i, "127.0.0.1", port)
        bots.append(bot)
        t = threading.Thread(target=connect_bot, args=(bot,), daemon=True)
        connection_threads.append(t)
        t.start()

    for t in connection_threads:
        t.join(timeout=5.0)

    connect_duration = time.time() - start_connect_time
    connected_count = sum(1 for b in bots if b.is_active)
    print(f"✅ [Stress Test] {connected_count}/{num_clients} Clients kết nối & đăng nhập thành công trong {connect_duration:.2f}s!")

    # 2. Bắt đầu gửi tải tin nhắn liên tục
    print(f"⚡ [Stress Test] Đang mô phỏng gửi tin nhắn ngẫu nhiên liên tục trong {duration_seconds} giây...")
    traffic_threads = []
    stop_traffic = threading.Event()

    def traffic_worker(b: BotClient):
        while not stop_traffic.is_set() and b.is_active:
            b.send_random_chat(bot_names)
            time.sleep(random.uniform(0.08, 0.25))

    traffic_start = time.time()
    for b in bots:
        t = threading.Thread(target=traffic_worker, args=(b,), daemon=True)
        traffic_threads.append(t)
        t.start()

    time.sleep(duration_seconds)
    stop_traffic.set()

    for t in traffic_threads:
        t.join(timeout=2.0)

    traffic_elapsed = time.time() - traffic_start

    # Chờ 0.5s để server phân phối nốt gói tin tồn đọng
    time.sleep(0.5)

    total_sent = sum(b.messages_sent for b in bots)
    total_broadcast = sum(b.broadcast_sent for b in bots)
    total_direct = sum(b.direct_sent for b in bots)
    total_received = sum(b.messages_received for b in bots)
    expected_received = (total_broadcast * connected_count) + total_direct
    delivery_ratio = (total_received / expected_received * 100.0) if expected_received > 0 else 0.0
    msg_rate = total_sent / traffic_elapsed if traffic_elapsed > 0 else 0

    print(f"📊 [Stress Test Metrics]:")
    print(f"   - Tổng số Clients hoạt động: {connected_count}/{num_clients}")
    print(f"   - Thời gian test tải: {traffic_elapsed:.2f}s")
    print(f"   - Tổng số tin nhắn đã gửi: {total_sent} messages (Broadcast: {total_broadcast}, Direct: {total_direct} | {msg_rate:.1f} msgs/sec)")
    print(f"   - Tổng số lượt tin nhắn nhận: {total_received}/{expected_received} deliveries ({delivery_ratio:.1f}%)")

    # 3. Dọn dẹp ngắt kết nối toàn bộ bot
    print("🔌 [Stress Test] Đang ngắt kết nối an toàn toàn bộ clients...")
    for b in bots:
        b.stop()

    server.stop()
    sthread.join(timeout=2.0)
    print("✅ [Stress Test] Hoàn tất bài kiểm thử tải thành công, Server dọn dẹp sạch sẽ!\n")

    return {
        "num_clients": num_clients,
        "connected_count": connected_count,
        "total_sent": total_sent,
        "total_broadcast": total_broadcast,
        "total_direct": total_direct,
        "total_received": total_received,
        "expected_received": expected_received,
        "delivery_ratio": delivery_ratio,
        "msg_rate": msg_rate,
    }


def test_concurrent_stress_load():
    """Hàm test dành riêng cho pytest thực thi tự động (15 clients)."""
    results = run_stress_test(num_clients=15, duration_seconds=4.0)
    assert results["connected_count"] == 15, "Tất cả 15 clients phải kết nối thành công!"
    assert results["total_sent"] >= 50, "Hệ thống phải xử lý gửi tối thiểu 50 tin nhắn!"
    assert results["expected_received"] > 0
    assert results["delivery_ratio"] >= 98.0, (
        f"Tỷ lệ phân phối tin nhắn dưới tải cao phải đạt >= 98%, thực tế: {results['delivery_ratio']:.2f}%"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stress Test cho Distributed Collaboration Server")
    parser.add_argument("--clients", type=int, default=16, help="Số lượng client đồng thời (Mặc định: 16)")
    parser.add_argument("--duration", type=float, default=6.0, help="Thời gian gửi tải tính bằng giây (Mặc định: 6.0)")
    args = parser.parse_args()

    results = run_stress_test(num_clients=args.clients, duration_seconds=args.duration)
    if results["connected_count"] == args.clients and results["total_sent"] > 0:
        sys.exit(0)
    else:
        sys.exit(1)
