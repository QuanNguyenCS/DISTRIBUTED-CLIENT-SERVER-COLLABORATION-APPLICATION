"""
Module: client.heartbeat
Mô tả: Quản lý luồng nhịp tim (Heartbeat / Keepalive) chạy ngầm phía Client.
Định kỳ gửi gói tin HEARTBEAT_PING lên Server để duy trì phiên kết nối
và phát hiện sớm sự cố mất mạng (Half-Open Sockets).
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Optional

from common.logger import get_logger
from common.message_types import MessageType

if TYPE_CHECKING:
    from client.client_core import ClientCore

logger = get_logger("client.heartbeat")


class HeartbeatSender(threading.Thread):
    """
    Luồng độc lập định kỳ gửi HEARTBEAT_PING lên Server.
    """

    def __init__(
        self,
        client: ClientCore,
        interval_seconds: float = 4.0,
    ) -> None:
        super().__init__(name=f"Heartbeat-{client.client_name}", daemon=True)
        self.client = client
        self.interval = interval_seconds
        self.is_running: bool = False
        self._stop_event = threading.Event()

    def run(self) -> None:
        self.is_running = True
        logger.info("💓 Luồng Heartbeat bắt đầu hoạt động (Chu kỳ: %.1fs)...", self.interval)

        while not self._stop_event.is_set() and self.client.is_connected:
            # Gửi gói tin PING
            try:
                ping_payload = {
                    "client": self.client.username or self.client.client_name,
                    "timestamp": time.time(),
                }
                success = self.client.send_packet(
                    MessageType.HEARTBEAT_PING,
                    ping_payload,
                )
                if not success:
                    logger.warning("Không thể gửi HEARTBEAT_PING tới server.")
                    break
            except Exception as e:
                logger.error("Lỗi trong luồng Heartbeat: %s", e)
                break

            # Chờ chu kỳ tiếp theo hoặc sự kiện dừng
            if self._stop_event.wait(timeout=self.interval):
                break

        self.is_running = False
        logger.info("🛑 Luồng Heartbeat đã dừng.")

    def stop(self) -> None:
        """Dừng luồng gửi nhịp tim."""
        self._stop_event.set()
