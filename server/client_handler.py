"""
Module: server.client_handler
Mô tả: Lớp ClientHandler kế thừa từ threading.Thread để chuyên trách giao tiếp
với một Client duy nhất. Áp dụng mô hình đa luồng Thread-per-Client, giúp Server
phục vụ đồng thời hàng chục Client mà không bị nghẽn (Non-blocking I/O).
"""

from __future__ import annotations

import socket
import threading
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Tuple

from cryptography.fernet import InvalidToken

from common.logger import get_logger
from common.message_types import MessageType
from common.protocol import (
    FLAG_ENCRYPTED,
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

        # Quản lý xác thực và danh tính người dùng
        self.is_authenticated: bool = False
        self.username: Optional[str] = None

        # Giám sát nhịp tim (Liveness / Heartbeat tracking)
        self.last_seen: float = time.time()

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
                if packet.is_encrypted and self.server.crypto_key is not None:
                    try:
                        packet = packet.get_decrypted_packet(self.server.crypto_key)
                    except InvalidToken:
                        logger.warning(
                            "⚠️ [%s:%d] Không thể giải mã gói tin bằng khóa Server (Client dùng khóa E2EE riêng?).",
                            self.client_addr[0],
                            self.client_addr[1],
                        )
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
        # Cập nhật thời điểm nhận gói tin cuối cùng từ Client
        self.last_seen = time.time()
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

        elif msg_type == MessageType.AUTH_REQ:
            # Xử lý yêu cầu xác thực / đăng nhập
            try:
                auth_payload = packet.to_json()
                req_username = auth_payload.get("username", "") if isinstance(auth_payload, dict) else packet.to_text()
            except Exception:
                req_username = packet.to_text()

            if self.is_authenticated:
                fail_payload = {
                    "status": "FAIL",
                    "reason": f"Bạn đã đăng nhập với tên '{self.username}'.",
                }
                self.send_packet(MessageType.AUTH_RESP_FAIL, fail_payload)
                return

            success, reason, session = self.server.session_mgr.register_user(
                username=req_username,
                handler=self,
                address=self.client_addr,
            )

            if not success or not session:
                fail_payload = {"status": "FAIL", "reason": reason}
                self.send_packet(MessageType.AUTH_RESP_FAIL, fail_payload)
            else:
                self.is_authenticated = True
                self.username = session.username
                self.client_name = session.username

                # Phản hồi đăng nhập thành công kèm danh sách user hiện tại
                success_payload = {
                    "status": "SUCCESS",
                    "username": self.username,
                    "online_users": self.server.session_mgr.get_all_users(),
                    "message": "Đăng nhập thành công.",
                }
                self.send_packet(MessageType.AUTH_RESP_SUCCESS, success_payload)

                # Phát thông báo cho tất cả client khác biết có người vừa tham gia
                join_broadcast = {
                    "event": "JOINED",
                    "username": self.username,
                    "online_count": self.server.session_mgr.get_user_count(),
                    "timestamp": time.time(),
                }
                self.server.broadcast_packet(
                    MessageType.USER_STATUS_BROADCAST,
                    join_broadcast,
                    exclude_addr=self.client_addr,
                )

        elif msg_type == MessageType.USER_LIST_REQ:
            # Trả về danh sách tất cả các user đang online
            online_users = self.server.session_mgr.get_all_users()
            list_payload = {
                "users": online_users,
                "count": len(online_users),
            }
            self.send_packet(MessageType.USER_LIST_RESP, list_payload)

        elif msg_type == MessageType.HEARTBEAT_PING:
            # Phản hồi ngay PONG để giữ nhịp tim
            self.send_packet(MessageType.HEARTBEAT_PONG, {"status": "ALIVE"})

        elif msg_type == MessageType.CHAT_BROADCAST:
            if packet.is_encrypted:
                # Server không có khóa giải mã (chế độ E2EE Client-to-Client):
                # Chuyển tiếp nguyên vẹn payload đã mã hóa và giữ nguyên cờ FLAG_ENCRYPTED!
                sender_name = self.username if self.is_authenticated else self.client_name
                logger.info(
                    "🔒📢 [Encrypted Broadcast Relay] từ '%s' (%d bytes ciphertext)",
                    sender_name,
                    len(packet.payload),
                )
                self.server.broadcast_packet(
                    MessageType.CHAT_BROADCAST,
                    packet.payload,
                    flags=packet.flags,
                )
                return

            # Định tuyến phát thanh tin nhắn phòng chung qua Router
            try:
                chat_data = packet.to_json()
                content = chat_data.get("content") or chat_data.get("text", "")
                timestamp = chat_data.get("timestamp")
            except Exception:
                content = packet.to_text()
                timestamp = None

            sender_name = self.username if self.is_authenticated else self.client_name
            self.server.router.route_broadcast_message(
                sender_username=sender_name,
                content=content,
                sender_handler=self,
                timestamp=timestamp,
            )

        elif msg_type == MessageType.CHAT_DIRECT:
            if packet.is_encrypted:
                self.send_packet(
                    MessageType.ERROR_NOTICE,
                    {
                        "code": "E2EE_ROUTING_REQUIRED",
                        "message": "Server không thể đọc tên người nhận vì toàn bộ gói tin CHAT_DIRECT bị mã hóa.",
                    },
                )
                return

            # Định tuyến tin nhắn riêng 1-1 (Unicast) qua Router
            e2ee_ciphertext: Optional[str] = None
            try:
                chat_data = packet.to_json()
                recipient = chat_data.get("recipient", "")
                if chat_data.get("e2ee") and "ciphertext" in chat_data:
                    e2ee_ciphertext = str(chat_data["ciphertext"])
                    content = "[Tin nhắn mã hóa E2EE]"
                else:
                    content = chat_data.get("content") or chat_data.get("text", "")
                timestamp = chat_data.get("timestamp")
            except Exception:
                recipient = ""
                content = packet.to_text()
                timestamp = None

            sender_name = self.username if self.is_authenticated else self.client_name
            self.server.router.route_direct_message(
                sender_username=sender_name,
                recipient_username=recipient,
                content=content,
                sender_handler=self,
                timestamp=timestamp,
                e2ee_ciphertext=e2ee_ciphertext,
            )

        elif msg_type == MessageType.CHAT_ACK:
            logger.debug("[%s] Nhận CHAT_ACK từ client.", self.client_name)

        elif msg_type == MessageType.FILE_OFFER_REQ:
            # Chuyển tiếp đề nghị gửi file
            try:
                offer_data = packet.to_json()
            except Exception:
                offer_data = {}
            self.server.router.route_file_offer(
                sender_username=self.username or self.client_name,
                offer_data=offer_data,
                sender_handler=self,
            )

        elif msg_type == MessageType.FILE_OFFER_RESP:
            # Chuyển tiếp phản hồi nhận file
            try:
                resp_data = packet.to_json()
            except Exception:
                resp_data = {}
            self.server.router.route_file_offer_response(
                recipient_username=self.username or self.client_name,
                resp_data=resp_data,
            )

        elif msg_type == MessageType.FILE_CHUNK:
            if packet.is_encrypted:
                logger.warning(
                    "⚠️ [%s] Nhận FILE_CHUNK có cờ FLAG_ENCRYPTED nhưng Server không có khóa giải mã metadata.",
                    self.username or self.client_name,
                )
                return

            # Chuyển tiếp mảnh dữ liệu file
            self.server.router.route_file_chunk(
                sender_username=self.username or self.client_name,
                chunk_payload=packet.payload,
            )

        elif msg_type == MessageType.FILE_ACK:
            # Chuyển tiếp xác nhận nhận file
            try:
                ack_data = packet.to_json()
            except Exception:
                ack_data = {}
            self.server.router.route_file_ack(
                recipient_username=self.username or self.client_name,
                ack_data=ack_data,
            )

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
            encrypt_target = (
                self.server.crypto_key is not None
                and not (flags & FLAG_ENCRYPTED)
                and int(msg_type) in (
                    MessageType.CHAT_BROADCAST,
                    MessageType.CHAT_DIRECT,
                    MessageType.FILE_CHUNK,
                )
            )
            packet_bytes = create_packet(
                msg_type,
                payload,
                flags=flags,
                encrypt_key=self.server.crypto_key if encrypt_target else None,
            )
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
        Đóng socket và hủy đăng ký khỏi ServerCore và SessionManager.
        """
        self.is_running = False
        if self.client_sock:
            try:
                self.client_sock.close()
            except OSError:
                pass
            finally:
                self.client_sock = None

        # 1. Hủy đăng ký phiên người dùng nếu đã đăng nhập và phát thanh thông báo LEFT
        if self.is_authenticated and self.username:
            username_left = self.username
            self.server.session_mgr.unregister_user(username_left)
            self.is_authenticated = False
            self.username = None

            left_broadcast = {
                "event": "LEFT",
                "username": username_left,
                "online_count": self.server.session_mgr.get_user_count(),
                "timestamp": time.time(),
            }
            self.server.broadcast_packet(
                MessageType.USER_STATUS_BROADCAST,
                left_broadcast,
                exclude_addr=self.client_addr,
            )
        else:
            # Dự phòng: Hủy theo handler nếu có
            removed_session = self.server.session_mgr.unregister_by_handler(self)
            if removed_session:
                left_broadcast = {
                    "event": "LEFT",
                    "username": removed_session.username,
                    "online_count": self.server.session_mgr.get_user_count(),
                    "timestamp": time.time(),
                }
                self.server.broadcast_packet(
                    MessageType.USER_STATUS_BROADCAST,
                    left_broadcast,
                    exclude_addr=self.client_addr,
                )

        # 2. Báo cho Server dọn dẹp handler này khỏi danh sách quản lý
        self.server.unregister_handler(self.client_addr)
        logger.info(
            "🛑 Đã đóng kết nối và dọn dẹp tài nguyên của [%s:%d].",
            self.client_addr[0],
            self.client_addr[1],
        )

