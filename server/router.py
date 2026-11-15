"""
Module: server.router
Mô tả: Bộ định tuyến tin nhắn (Message Router) chịu trách nhiệm phân phối gói tin:
  - Broadcast: Định tuyến tin nhắn đến toàn bộ người dùng đang online trong phòng chat.
  - Unicast (Direct Message): Định tuyến tin nhắn riêng 1-1 đến chính xác người nhận,
    bảo mật thông tin trước các người dùng khác và báo lỗi nếu người nhận không tồn tại.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from common.logger import get_logger
from common.message_types import MessageType

if TYPE_CHECKING:
    from server.client_handler import ClientHandler
    from server.server_core import ServerCore

logger = get_logger("server.router")


class MessageRouter:
    """
    Bộ điều phối và định tuyến tin nhắn của Server (Broadcast & Unicast 1-1).
    Truyền file được thực hiện P2P trực tiếp giữa các Client sau khi Lookup từ Tracker.
    """

    def __init__(self, server: ServerCore) -> None:
        self.server = server

    def route_broadcast_message(
        self,
        sender_username: str,
        content: str,
        sender_handler: Optional[ClientHandler] = None,
        timestamp: Optional[float] = None,
    ) -> Tuple[bool, int]:
        """
        Định tuyến tin nhắn phòng chung tới tất cả người dùng đang online.

        Args:
            sender_username: Tên người gửi.
            content: Nội dung văn bản tin nhắn.
            sender_handler: Luồng handler của người gửi (nếu có).
            timestamp: Dấu thời gian (giây), mặc định lấy thời gian hiện tại.

        Returns:
            Tuple[bool, int]: (Thành công hay không, Số lượng client đã nhận tin).
        """
        if not content:
            return False, 0

        ts = timestamp if timestamp is not None else time.time()
        broadcast_payload = {
            "sender": sender_username,
            "content": content,
            "text": content,  # Hỗ trợ tương thích ngược cho cả text và content
            "timestamp": ts,
            "type": "broadcast",
        }

        logger.info("📢 [Broadcast] %s: %s", sender_username, content)

        # Phát tán cho tất cả các client đang online
        success_count = self.server.broadcast_packet(
            MessageType.CHAT_BROADCAST,
            broadcast_payload,
        )

        return True, success_count

    def route_direct_message(
        self,
        sender_username: str,
        recipient_username: str,
        content: str,
        sender_handler: Optional[ClientHandler] = None,
        timestamp: Optional[float] = None,
        e2ee_ciphertext: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Định tuyến tin nhắn riêng 1-1 (Unicast) đến một người nhận cụ thể.

        Args:
            sender_username: Tên người gửi.
            recipient_username: Tên người nhận.
            content: Nội dung tin nhắn.
            sender_handler: Handler của người gửi (để phản hồi ACK hoặc báo lỗi).
            timestamp: Dấu thời gian (giây).
            e2ee_ciphertext: Chuỗi mã hóa E2EE (nếu Server chỉ chuyển tiếp không giữ khóa).

        Returns:
            Tuple[bool, str]: (Thành công hay không, Thông điệp kết quả).
        """
        if not content and not e2ee_ciphertext:
            return False, "Nội dung tin nhắn không được để trống."

        # 1. Chặn việc tự gửi tin nhắn riêng cho chính mình
        if sender_username.strip().lower() == recipient_username.strip().lower():
            reason = "Không thể gửi tin nhắn riêng cho chính mình."
            logger.warning("[%s] Cố tình gửi tin nhắn riêng cho chính mình.", sender_username)
            if sender_handler:
                sender_handler.send_packet(
                    MessageType.ERROR_NOTICE,
                    {"code": "SELF_MESSAGE_NOT_ALLOWED", "message": reason},
                )
            return False, reason

        # 2. Tra cứu phiên người nhận trong SessionManager
        session = self.server.session_mgr.get_session(recipient_username)
        if not session or not session.handler:
            reason = f"Người dùng '{recipient_username}' hiện không online hoặc không tồn tại."
            logger.warning(
                "[%s -> %s] Thất bại: %s",
                sender_username,
                recipient_username,
                reason,
            )
            # Báo lỗi về cho riêng người gửi
            if sender_handler:
                sender_handler.send_packet(
                    MessageType.ERROR_NOTICE,
                    {
                        "code": "USER_NOT_FOUND",
                        "recipient": recipient_username,
                        "message": reason,
                    },
                )
            return False, reason

        ts = timestamp if timestamp is not None else time.time()

        # 3. Đóng gói và gửi tin nhắn riêng tới người nhận
        if e2ee_ciphertext is not None:
            direct_payload: Dict[str, Any] = {
                "sender": sender_username,
                "recipient": session.username,
                "e2ee": True,
                "ciphertext": e2ee_ciphertext,
                "timestamp": ts,
                "type": "direct",
            }
        else:
            direct_payload = {
                "sender": sender_username,
                "recipient": session.username,  # Giữ đúng chữ hoa/thường chuẩn của người nhận
                "content": content,
                "timestamp": ts,
                "type": "direct",
            }

        sent = session.handler.send_packet(
            MessageType.CHAT_DIRECT,
            direct_payload,
        )

        if not sent:
            reason = f"Không thể chuyển tiếp tin nhắn tới '{session.username}' do lỗi kết nối socket."
            logger.error("[%s -> %s] %s", sender_username, session.username, reason)
            if sender_handler:
                sender_handler.send_packet(
                    MessageType.ERROR_NOTICE,
                    {"code": "DELIVERY_FAILED", "message": reason},
                )
            return False, reason

        logger.info("🔒 [Direct] %s ➔ %s: %s", sender_username, session.username, content)

        # 4. Gửi xác nhận CHAT_ACK về cho người gửi để hiển thị đã gửi thành công
        if sender_handler:
            ack_payload = {
                "status": "DELIVERED",
                "recipient": session.username,
                "content": content,
                "timestamp": ts,
            }
            sender_handler.send_packet(MessageType.CHAT_ACK, ack_payload)

        return True, "Tin nhắn riêng đã được gửi thành công."
