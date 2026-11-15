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
from client.file_transfer import unpack_chunk_payload

if TYPE_CHECKING:
    from server.client_handler import ClientHandler
    from server.server_core import ServerCore

logger = get_logger("server.router")


class MessageRouter:
    """
    Bộ điều phối và định tuyến tin nhắn của Server.
    
    Tương tác trực tiếp với SessionManager để tra cứu danh bạ người dùng trực tuyến
    và ClientHandler để gửi gói tin xuống tầng socket.
    """

    def __init__(self, server: ServerCore) -> None:
        self.server = server
        # Bản đồ file_id -> (sender_username, recipient_username)
        self._file_routes: Dict[str, Tuple[str, str]] = {}

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

    # ==========================================================================
    # CÁC PHƯƠNG THỨC ĐỊNH TUYẾN TRUYỀN FILE (FILE TRANSFER RELAY)
    # ==========================================================================
    def route_file_offer(
        self,
        sender_username: str,
        offer_data: Dict[str, Any],
        sender_handler: Optional[ClientHandler] = None,
    ) -> bool:
        """Chuyển tiếp đề xuất gửi file (FILE_OFFER_REQ) tới người nhận."""
        recipient = offer_data.get("recipient", "")
        file_id = offer_data.get("file_id", "")

        session = self.server.session_mgr.get_session(recipient)
        if not session or not session.handler:
            logger.warning("Truyền file thất bại: Người nhận '%s' không online.", recipient)
            if sender_handler:
                sender_handler.send_packet(
                    MessageType.FILE_OFFER_RESP,
                    {
                        "file_id": file_id,
                        "status": "REJECTED",
                        "reason": f"Người nhận '{recipient}' không online.",
                    },
                )
            return False

        # Lưu ánh xạ file_id để chuyển tiếp các chunk tiếp theo
        self._file_routes[file_id] = (sender_username, session.username)

        logger.info(
            "📁 [File Offer] %s đề xuất gửi file '%s' (%s bytes) cho %s",
            sender_username,
            offer_data.get("file_name"),
            offer_data.get("file_size"),
            session.username,
        )

        return session.handler.send_packet(MessageType.FILE_OFFER_REQ, offer_data)

    def route_file_offer_response(
        self,
        recipient_username: str,
        resp_data: Dict[str, Any],
    ) -> bool:
        """Chuyển tiếp phản hồi đồng ý/từ chối nhận file (FILE_OFFER_RESP) về cho người gửi."""
        file_id = resp_data.get("file_id", "")
        route = self._file_routes.get(file_id)

        sender_username = resp_data.get("sender") or (route[0] if route else "")
        session = self.server.session_mgr.get_session(sender_username)
        if not session or not session.handler:
            logger.warning("Không tìm thấy người gửi '%s' để trả lời FILE_OFFER_RESP.", sender_username)
            return False

        return session.handler.send_packet(MessageType.FILE_OFFER_RESP, resp_data)

    def route_file_chunk(
        self,
        sender_username: str,
        chunk_payload: bytes,
    ) -> bool:
        """Chuyển tiếp mảnh dữ liệu file (FILE_CHUNK) tới người nhận."""
        try:
            meta, _ = unpack_chunk_payload(chunk_payload)
            file_id = meta.get("file_id", "")
        except Exception as e:
            logger.error("Lỗi giải mã FILE_CHUNK: %s", e)
            return False

        route = self._file_routes.get(file_id)
        if not route:
            logger.warning("Không tìm thấy tuyến đường cho file_id '%s'", file_id)
            return False

        recipient_username = route[1]
        session = self.server.session_mgr.get_session(recipient_username)
        if not session or not session.handler:
            return False

        # Chuyển tiếp nguyên vẹn payload nhị phân sang người nhận (zero-copy relay)
        return session.handler.send_packet(MessageType.FILE_CHUNK, chunk_payload)

    def route_file_ack(
        self,
        recipient_username: str,
        ack_data: Dict[str, Any],
    ) -> bool:
        """Chuyển tiếp xác nhận hoàn tất nhận file (FILE_ACK) về cho người gửi."""
        file_id = ack_data.get("file_id", "")
        route = self._file_routes.pop(file_id, None)

        sender_username = ack_data.get("sender") or (route[0] if route else "")
        session = self.server.session_mgr.get_session(sender_username)
        if not session or not session.handler:
            return False

        return session.handler.send_packet(MessageType.FILE_ACK, ack_data)
