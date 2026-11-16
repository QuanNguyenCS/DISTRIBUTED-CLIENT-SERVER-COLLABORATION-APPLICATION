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
        self.client_info = client_info if isinstance(client_info, dict) else {}
        raw_name = self.client_info.get("client_name")
        self.client_name: str = (
            raw_name.strip() if isinstance(raw_name, str) and raw_name.strip() else f"User@{client_addr[1]}"
        )
        self.is_running: bool = False
        self._send_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._closed: bool = False

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
                was_encrypted = packet.is_encrypted
                if packet.is_encrypted and self.server.crypto_key is not None:
                    try:
                        packet = packet.get_decrypted_packet(self.server.crypto_key)
                    except InvalidToken:
                        logger.warning(
                            "⚠️ [%s:%d] Không thể giải mã gói tin bằng khóa Server (sai mật khẩu phòng).",
                            self.client_addr[0],
                            self.client_addr[1],
                        )
                        self.send_packet(
                            MessageType.ERROR_NOTICE,
                            {
                                "code": "DECRYPTION_FAILED",
                                "message": "Không thể giải mã gói tin: Mật khẩu phòng (AES) không khớp với Server.",
                            },
                        )
                        continue
                self._dispatch_packet(packet, was_encrypted=was_encrypted)

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

    def _dispatch_packet(self, packet: Packet, was_encrypted: bool = False) -> None:
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

        # Auth Gate (F3): Chỉ cho phép AUTH_REQ, HEARTBEAT và DISCONNECT_NOTICE khi chưa đăng nhập
        if not self.is_authenticated and msg_type not in (
            MessageType.AUTH_REQ,
            MessageType.HEARTBEAT_PING,
            MessageType.HEARTBEAT_PONG,
            MessageType.DISCONNECT_NOTICE,
        ):
            logger.warning(
                "⛔ [%s:%d] Từ chối gói tin %s vì Client chưa xác thực (AUTH_REQ).",
                self.client_addr[0],
                self.client_addr[1],
                msg_type,
            )
            self.send_packet(
                MessageType.ERROR_NOTICE,
                {
                    "code": "AUTH_REQUIRED",
                    "message": "Vui lòng đăng nhập (AUTH_REQ) trước khi thực hiện thao tác này.",
                },
            )
            return

        # Anti-Downgrade Gate (F6 + Cách 1): Khi Server bật AES, chặn mọi gói nghiệp vụ gửi bản rõ
        if (
            self.server.crypto_key is not None
            and not was_encrypted
            and msg_type in (
                MessageType.AUTH_REQ,
                MessageType.USER_LIST_REQ,
                MessageType.PEER_LOOKUP_REQ,
                MessageType.CHAT_BROADCAST,
                MessageType.CHAT_DIRECT,
            )
        ):
            logger.warning(
                "🔒⛔ [%s:%d] Từ chối gói tin %s dạng bản rõ vì Server đang bắt buộc mã hóa AES.",
                self.client_addr[0],
                self.client_addr[1],
                msg_type,
            )
            self.send_packet(
                MessageType.ERROR_NOTICE,
                {
                    "code": "ENCRYPTION_REQUIRED",
                    "message": "Server đang bật mã hóa AES phòng chat: gói tin bắt buộc phải được mã hóa.",
                },
            )
            return

        if msg_type == MessageType.DISCONNECT_NOTICE:
            logger.info(
                "👋 [%s:%d] Client '%s' chủ động gửi DISCONNECT_NOTICE.",
                self.client_addr[0],
                self.client_addr[1],
                self.client_name,
            )
            self.is_running = False

        elif msg_type == MessageType.AUTH_REQ:
            # Xử lý yêu cầu xác thực / đăng nhập kèm đăng ký cổng P2P lên Tracker
            req_p2p_port: Optional[int] = None
            req_p2p_host: Optional[str] = None
            try:
                auth_payload = packet.to_json()
                if isinstance(auth_payload, dict):
                    req_username = auth_payload.get("username", "")
                    req_p2p_port = auth_payload.get("p2p_port")
                    req_p2p_host = auth_payload.get("p2p_host")
                else:
                    req_username = packet.to_text()
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
                p2p_port=req_p2p_port,
                p2p_host=req_p2p_host,
            )

            if not success or not session:
                fail_payload = {"status": "FAIL", "reason": reason}
                self.send_packet(MessageType.AUTH_RESP_FAIL, fail_payload)
            else:
                self.is_authenticated = True
                self.username = session.username
                self.client_name = session.username

                # Phản hồi đăng nhập thành công kèm danh sách user & danh bạ P2P hiện tại
                success_payload = {
                    "status": "SUCCESS",
                    "username": self.username,
                    "online_users": self.server.session_mgr.get_all_users(),
                    "peers": self.server.session_mgr.get_all_peer_endpoints(),
                    "message": "Đăng nhập thành công.",
                }
                self.send_packet(MessageType.AUTH_RESP_SUCCESS, success_payload)

                # Phát thông báo cho tất cả client khác biết có người vừa tham gia kèm danh sách online
                self._broadcast_user_status(
                    event="JOINED",
                    username=self.username,
                    peer=session.to_peer_dict() if session.p2p_port is not None else None,
                )

        elif msg_type == MessageType.USER_LIST_REQ:
            # Trả về danh sách tất cả các user đang online kèm danh bạ IP:P2P_Port
            online_users = self.server.session_mgr.get_all_users()
            list_payload = {
                "users": online_users,
                "peers": self.server.session_mgr.get_all_peer_endpoints(),
                "count": len(online_users),
            }
            self.send_packet(MessageType.USER_LIST_RESP, list_payload)

        elif msg_type == MessageType.PEER_LOOKUP_REQ:
            # Control Plane Tracker: Tra cứu địa chỉ IP:P2P_Port cho Client
            try:
                lookup_data = packet.to_json()
                target = str(
                    lookup_data.get("target") or lookup_data.get("username") or ""
                ).strip()
            except Exception:
                target = ""

            if not target:
                self.send_packet(
                    MessageType.PEER_LOOKUP_RESP,
                    {
                        "found": False,
                        "target": "",
                        "username": "",
                        "reason": "Thiếu tên người nhận cần tra cứu P2P.",
                    },
                )
                return

            session = self.server.session_mgr.get_session(target)
            if not session or not session.handler:
                self.send_packet(
                    MessageType.PEER_LOOKUP_RESP,
                    {
                        "found": False,
                        "target": target,
                        "username": target,
                        "reason": f"Người dùng '{target}' hiện không online hoặc không tồn tại.",
                    },
                )
                return

            if session.p2p_port is None:
                self.send_packet(
                    MessageType.PEER_LOOKUP_RESP,
                    {
                        "found": False,
                        "target": target,
                        "username": session.username,
                        "reason": f"Người dùng '{session.username}' chưa mở cổng nhận file P2P.",
                    },
                )
                return

            logger.info(
                "🔍 [Tracker Lookup] %s hỏi địa chỉ P2P của %s -> %s:%d",
                self.username or self.client_name,
                session.username,
                session.effective_ip,
                session.p2p_port,
            )
            self.send_packet(
                MessageType.PEER_LOOKUP_RESP,
                {
                    "found": True,
                    "target": target,
                    "username": session.username,
                    "ip": session.effective_ip,
                    "p2p_port": session.p2p_port,
                },
            )

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
                    only_authenticated=True,
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

        elif msg_type in (
            MessageType.FILE_OFFER_REQ,
            MessageType.FILE_OFFER_RESP,
            MessageType.FILE_CHUNK,
            MessageType.FILE_ACK,
        ):
            logger.warning(
                "⚠️ [%s] Từ chối chuyển tiếp gói tin %s qua Server: truyền file chỉ hỗ trợ P2P trực tiếp.",
                self.username or self.client_name,
                msg_type,
            )
            self.send_packet(
                MessageType.ERROR_NOTICE,
                {
                    "code": "FILE_P2P_ONLY",
                    "message": "Server chỉ đóng vai trò Tracker (Lookup IP:P2P_Port); truyền file phải thực hiện trực tiếp P2P giữa 2 Client.",
                },
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
                    MessageType.AUTH_RESP_SUCCESS,
                    MessageType.AUTH_RESP_FAIL,
                    MessageType.USER_LIST_RESP,
                    MessageType.USER_STATUS_BROADCAST,
                    MessageType.PEER_LOOKUP_RESP,
                    MessageType.CHAT_BROADCAST,
                    MessageType.CHAT_DIRECT,
                    MessageType.CHAT_ACK,
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

    def _broadcast_user_status(
        self,
        event: str,
        username: str,
        peer: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Phát thanh sự kiện JOINED/LEFT kèm danh sách online và danh bạ P2P mới nhất
        tới toàn bộ các client khác đang kết nối.
        """
        online_users = self.server.session_mgr.get_all_users()
        payload: Dict[str, Any] = {
            "event": event,
            "username": username,
            "online_users": online_users,
            "peers": self.server.session_mgr.get_all_peer_endpoints(),
            "online_count": len(online_users),
            "timestamp": time.time(),
        }
        if peer is not None:
            payload["peer"] = peer
        self.server.broadcast_packet(
            MessageType.USER_STATUS_BROADCAST,
            payload,
            exclude_addr=self.client_addr,
            only_authenticated=True,
        )

    def close(self) -> None:
        """
        Đóng socket và hủy đăng ký khỏi ServerCore và SessionManager (Idempotent & Thread-Safe).
        """
        with self._close_lock:
            if self._closed:
                return
            self._closed = True

        self.is_running = False
        if self.client_sock:
            try:
                self.client_sock.close()
            except OSError:
                pass
            finally:
                self.client_sock = None

        # 1. Hủy đăng ký phiên người dùng nếu đã đăng nhập và phát thanh thông báo LEFT (tránh trùng lặp)
        if self.is_authenticated and self.username:
            username_left = self.username
            self.is_authenticated = False
            self.username = None
            removed = self.server.session_mgr.unregister_user(username_left)
            if removed:
                self._broadcast_user_status(event="LEFT", username=removed.username)
        else:
            # Dự phòng: Hủy theo handler nếu có
            removed_session = self.server.session_mgr.unregister_by_handler(self)
            if removed_session:
                self._broadcast_user_status(event="LEFT", username=removed_session.username)

        # 2. Báo cho Server dọn dẹp handler này khỏi danh sách quản lý
        self.server.unregister_handler(self.client_addr)
        logger.info(
            "🛑 Đã đóng kết nối và dọn dẹp tài nguyên của [%s:%d].",
            self.client_addr[0],
            self.client_addr[1],
        )

