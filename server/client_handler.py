"""
Module: server.client_handler
Mô tả: Lớp ClientHandler kế thừa từ threading.Thread để chuyên trách giao tiếp
với một Client duy nhất. Áp dụng mô hình đa luồng Thread-per-Client, giúp Server
phục vụ đồng thời hàng chục Client mà không bị nghẽn (Non-blocking I/O).
"""

from __future__ import annotations

import socket
import threading
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Tuple

from common.logger import get_logger
from common.message_types import MessageType
from common.protocol import (
    ConnectionClosedError,
    Packet,
    ProtocolError,
    create_packet,
    recv_packet,
)

if TYPE_CHECKING:
    from server.server_core import ServerCore

logger = get_logger("server.handler")


class ClientHandler(threading.Thread):
    """
    Luồng độc lập chuyên trách một kết nối Client.
    
    Vòng đời của ClientHandler:
      1. Khởi tạo với client_sock, client_addr và tham chiếu tới ServerCore.
      2. Chạy phương thức run() trên một Thread riêng biệt (Daemon Thread).
      3. Lặp liên tục lắng nghe các gói tin từ Client bằng recv_packet().
      4. Xử lý các loại thông điệp (CHAT, PING, FILE, DISCONNECT...).
      5. Khi Client ngắt kết nối hoặc có sự cố, dọn dẹp socket và thông báo cho ServerCore.
    """

    def __init__(
        self,
        client_sock: socket.socket,
        client_addr: Tuple[str, int],
        server: ServerCore,
        client_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        # Đặt tên thread để dễ trace log: Handler-127.0.0.1:54321
        thread_name = f"Handler-{client_addr[0]}:{client_addr[1]}"
        super().__init__(name=thread_name, daemon=True)

        self.client_sock = client_sock
        self.client_addr = client_addr
        self.server = server
        self.client_info = client_info or {}
        self.client_name: str = self.client_info.get("client_name", f"User@{client_addr[1]}")
        self.is_running: bool = False
        self._send_lock = threading.Lock()

    def run(self) -> None:
        """
        Vòng lặp lắng nghe chính chạy trong luồng riêng.
        """
        self.is_running = True
        logger.info(
            "🧵 Luồng [%s] bắt đầu phục vụ client '%s' (%s:%d)",
            self.name,
            self.client_name,
            self.client_addr[0],
            self.client_addr[1],
        )

        try:
            while self.is_running:
                # Đọc gói tin hoàn chỉnh theo chuẩn Application Layer Framing
                packet = recv_packet(self.client_sock)
                self._dispatch_packet(packet)

        except ConnectionClosedError:
            logger.info(
                "🔌 [%s:%d] Client '%s' đã ngắt kết nối.",
                self.client_addr[0],
                self.client_addr[1],
                self.client_name,
            )
        except (ConnectionResetError, ConnectionAbortedError):
            logger.warning(
                "⚠️ [%s:%d] Kết nối tới client '%s' bị reset đột ngột.",
                self.client_addr[0],
                self.client_addr[1],
                self.client_name,
            )
        except ProtocolError as exc:
            logger.error(
                "❌ [%s:%d] Vi phạm giao thức từ client '%s': %s",
                self.client_addr[0],
                self.client_addr[1],
                self.client_name,
                exc,
            )
        except OSError as exc:
            if self.is_running:
                logger.error(
                    "❌ [%s:%d] Lỗi Socket với client '%s': %s",
                    self.client_addr[0],
                    self.client_addr[1],
                    self.client_name,
                    exc,
                )
        finally:
            self.close()

    def _dispatch_packet(self, packet: Packet) -> None:
        """
        Phân loại và điều hướng xử lý gói tin nhận được.
        """
        msg_type = packet.msg_type
        logger.debug(
            "[%s:%d] Nhận gói tin mã %s (Payload: %d bytes)",
            self.client_addr[0],
            self.client_addr[1],
            msg_type,
            len(packet.payload),
        )

        if msg_type == MessageType.DISCONNECT_NOTICE:
            logger.info(
                "👋 [%s:%d] Client '%s' chủ động gửi DISCONNECT_NOTICE.",
                self.client_addr[0],
                self.client_addr[1],
                self.client_name,
            )
            self.is_running = False

        elif msg_type == MessageType.HEARTBEAT_PING:
            # Phản hồi ngay PONG để giữ nhịp tim
            self.send_packet(MessageType.HEARTBEAT_PONG, {"status": "ALIVE"})

        elif msg_type == MessageType.CHAT_BROADCAST:
            # Phát thanh tin nhắn cho tất cả các Client khác đang kết nối
            try:
                chat_data = packet.to_json()
                text = chat_data.get("text", "")
            except Exception:
                text = packet.to_text()

            logger.info("💬 [Phòng chung] %s: %s", self.client_name, text)

            broadcast_payload = {
                "sender": self.client_name,
                "text": text,
                "type": "broadcast",
            }
            # Server phát lại cho tất cả client (kể cả người gửi để xác nhận)
            self.server.broadcast_packet(
                MessageType.CHAT_BROADCAST,
                broadcast_payload,
            )

        elif msg_type == MessageType.CHAT_ACK:
            logger.debug("[%s] Nhận CHAT_ACK từ client.", self.client_name)

        else:
            logger.warning(
                "[%s:%d] Nhận loại gói tin chưa hỗ trợ xử lý ở giai đoạn này: %s",
                self.client_addr[0],
                self.client_addr[1],
                msg_type,
            )

    def send_packet(
        self,
        msg_type: MessageType | int,
        payload: bytes | str | dict | list = b"",
        flags: int = 0,
    ) -> bool:
        """
        Gửi một gói tin đến Client an toàn đa luồng (Thread-Safe).

        Args:
            msg_type: Loại thông điệp.
            payload: Dữ liệu (bytes, text hoặc json).
            flags: Cờ bitmask.

        Returns:
            bool: True nếu gửi thành công, False nếu kết nối đã hỏng.
        """
        if not self.is_running and not self.client_sock:
            return False

        try:
            packet_bytes = create_packet(msg_type, payload, flags=flags)
            with self._send_lock:
                if self.client_sock:
                    self.client_sock.sendall(packet_bytes)
            return True
        except (OSError, ConnectionError) as exc:
            logger.warning(
                "Không thể gửi gói tin tới [%s:%d]: %s",
                self.client_addr[0],
                self.client_addr[1],
                exc,
            )
            self.is_running = False
            return False

    def close(self) -> None:
        """
        Đóng socket và hủy đăng ký khỏi ServerCore.
        """
        self.is_running = False
        if self.client_sock:
            try:
                self.client_sock.close()
            except OSError:
                pass
            finally:
                self.client_sock = None

        # Báo cho Server dọn dẹp handler này khỏi danh sách quản lý
        self.server.unregister_handler(self.client_addr)
        logger.info(
            "🛑 Đã đóng kết nối và dọn dẹp tài nguyên của [%s:%d].",
            self.client_addr[0],
            self.client_addr[1],
        )
