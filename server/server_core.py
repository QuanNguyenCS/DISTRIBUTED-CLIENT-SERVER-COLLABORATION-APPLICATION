"""
Module: server.server_core
Mô tả: Lớp Server chính quản lý TCP Socket Listener, chấp nhận kết nối từ các Client,
thực hiện cơ chế bắt tay tầng ứng dụng và phân phối mỗi Client cho một ClientHandler Thread riêng.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common.peer_auth import public_key_text, sign
from common.discovery import DiscoveryResponder
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from common.crypto_utils import derive_key, get_shared_app_key
from common.logger import get_logger
from common.message_types import MessageType
from common.protocol import (
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    ConnectionClosedError,
    ProtocolError,
    create_packet,
    recv_packet,
)
from server.client_handler import ClientHandler
from server.router import MessageRouter
from server.session_manager import SessionManager

logger = get_logger("server.core")


class ServerCore:
    """
    Lớp quản lý Server TCP ở tầng mạng áp dụng mô hình Thread-per-Client.

    Vòng đời của Server Socket:
      1. Khởi tạo socket TCP: socket(AF_INET, SOCK_STREAM)
      2. Cấu hình cờ SO_REUSEADDR (tránh lỗi 'Address already in use' khi khởi động lại)
      3. Gán địa chỉ (bind) vào host và port quy định
      4. Lắng nghe (listen) với backlog xác định
      5. Chấp nhận kết nối (accept) và thực hiện bắt tay ứng dụng (Handshake)
      6. Chuyển giao socket client cho ClientHandler Thread riêng biệt để chạy song song
    """

    DEFAULT_HOST: str = "0.0.0.0"
    DEFAULT_PORT: int = 9000
    DEFAULT_BACKLOG: int = 20
    HANDSHAKE_TIMEOUT: float = 10.0
    HANDSHAKE_MAX_PAYLOAD: int = 64 * 1024
    MAX_PENDING_HANDSHAKES: int = 64
    MAX_ACTIVE_CONNECTIONS: int = 128

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        server_id: str = "CollabServer-01",
        auto_encrypt: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.server_id = server_id
        self.server_sock: Optional[socket.socket] = None
        self.is_running: bool = False
        self._lock = threading.RLock()

        # Quản lý danh sách các ClientHandler đang hoạt động theo (IP, Port)
        self.handlers: Dict[Tuple[str, int], ClientHandler] = {}
        self._handlers_lock = threading.Lock()
        self._broadcast_lock = threading.RLock()
        self._ticket_key = Ed25519PrivateKey.generate()
        self._discovery = None
        self._pending_sockets: Set[socket.socket] = set()
        self._handshake_sem = threading.BoundedSemaphore(self.MAX_PENDING_HANDSHAKES)

        # Quản lý phiên và trạng thái người dùng (Active User Sessions)
        self.session_mgr = SessionManager()

        # Bộ định tuyến tin nhắn (Message Router)
        self.router = MessageRouter(self)

        # Giám sát kết nối Zombie & Quản lý nhịp tim
        self.zombie_timeout: float = (
            15.0  # Quá 15 giây không có tín hiệu coi như mất mạng ngầm
        )
        self.zombie_check_interval: float = 3.0
        self._zombie_cleaner_thread: Optional[threading.Thread] = None
        self._stop_zombie_event = threading.Event()

        # Lớp Bảo mật & Mã hóa dữ liệu (Tự động bật AES-Fernet từ COLLAB_AES_KEY / mặc định)
        self.crypto_key: Optional[bytes] = (
            get_shared_app_key() if auto_encrypt else None
        )

    def enable_encryption(self, passphrase: Optional[str] = None) -> None:
        """Kích hoạt hoặc ghi đè khóa AES (Fernet) cho Server."""
        self.crypto_key = (
            get_shared_app_key(passphrase) if passphrase else get_shared_app_key()
        )
        if self._discovery is not None:
            self._discovery.key = self.crypto_key
        logger.info("🔒 Đã kích hoạt lớp mã hóa AES cho Server.")

    def disable_encryption(self) -> None:
        """Tắt mã hóa đối xứng trên Server."""
        self.crypto_key = None
        if self._discovery is not None:
            self._discovery.close()
            self._discovery = None
        logger.info("🔓 Đã tắt lớp mã hóa AES trên Server.")

    def start(self) -> None:
        """
        Khởi động TCP Server socket, bind và listen.
        """
        with self._lock:
            if self.is_running:
                logger.warning("Server đang chạy sẵn trên %s:%d.", self.host, self.port)
                return

            try:
                # 1. Tạo socket TCP IPv4
                self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                # 2. Bật SO_REUSEADDR để tái sử dụng port ngay khi khởi động lại server
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # 3. Bind socket vào host và port
                self.server_sock.bind((self.host, self.port))

                # 4. Bắt đầu lắng nghe các kết nối từ client
                self.server_sock.listen(self.DEFAULT_BACKLOG)
                self.port = self.server_sock.getsockname()[1]
                self.is_running = True
                if self.crypto_key is not None:
                    self._discovery = DiscoveryResponder(
                        self.host, self.port, self.server_id, self.crypto_key
                    )

                # 5. Khởi chạy luồng dọn dẹp Zombie kết nối ngầm
                self._stop_zombie_event.clear()
                self._zombie_cleaner_thread = threading.Thread(
                    target=self._run_zombie_cleaner,
                    name="ZombieCleanerThread",
                    daemon=True,
                )
                self._zombie_cleaner_thread.start()

                logger.info(
                    "🚀 Server '%s' đã khởi động thành công và đang lắng nghe tại %s:%d (Backlog: %d)",
                    self.server_id,
                    self.host,
                    self.port,
                    self.DEFAULT_BACKLOG,
                )
            except OSError as exc:
                logger.critical(
                    "Không thể khởi động Server tại %s:%d: %s",
                    self.host,
                    self.port,
                    exc,
                )
                self.stop()
                raise

    def handle_handshake(
        self,
        client_sock: socket.socket,
        client_addr: Tuple[str, int],
        timeout: Optional[float] = None,
        on_ready_before_ack: Optional[Callable[[dict], None]] = None,
    ) -> Tuple[bool, Optional[dict]]:
        """
        Thực hiện quy trình Bắt tay Ứng dụng (Application Handshake):
          1. Đọc gói tin HELLO_HANDSHAKE từ Client (dưới tổng deadline và giới hạn kích thước).
          2. Kiểm tra schema JSON object (dict) & phiên bản giao thức (Protocol Version).
          3. Nếu hợp lệ: Gọi on_ready_before_ack (nếu có) và gửi HANDSHAKE_ACK.
          4. Nếu không hợp lệ: Gửi HANDSHAKE_REJECT và thông báo lý do.
        """
        try:
            hs_timeout = self.HANDSHAKE_TIMEOUT if timeout is None else float(timeout)
            deadline = time.monotonic() + hs_timeout
            client_sock.settimeout(hs_timeout)

            # Bước 1: Nhận gói tin đầu tiên từ client với tổng deadline & cap 64KB
            packet = recv_packet(
                client_sock,
                max_payload_size=self.HANDSHAKE_MAX_PAYLOAD,
                deadline=deadline,
            )

            if packet.msg_type != MessageType.HELLO_HANDSHAKE:
                logger.warning(
                    "[%s:%d] Gói tin đầu tiên không phải HELLO_HANDSHAKE (Nhận mã: %s). Từ chối kết nối.",
                    client_addr[0],
                    client_addr[1],
                    packet.msg_type,
                )
                reject_payload = {
                    "status": "REJECT",
                    "reason": f"Expected HELLO_HANDSHAKE (101), received {packet.msg_type}",
                }
                client_sock.sendall(
                    create_packet(MessageType.HANDSHAKE_REJECT, reject_payload)
                )
                return False, None

            # Bước 2: Parse & kiểm tra schema JSON phải là object (dict)
            try:
                client_info = packet.to_json()
            except Exception as e:
                logger.warning(
                    "[%s:%d] Payload HELLO_HANDSHAKE không phải JSON hợp lệ: %s",
                    client_addr[0],
                    client_addr[1],
                    e,
                )
                client_sock.sendall(
                    create_packet(
                        MessageType.HANDSHAKE_REJECT,
                        {
                            "status": "REJECT",
                            "reason": "HELLO_HANDSHAKE payload must be valid JSON.",
                        },
                    )
                )
                return False, None

            if not isinstance(client_info, dict):
                logger.warning(
                    "[%s:%d] Payload HELLO_HANDSHAKE sai kiểu (%s, yêu cầu dict). Từ chối bắt tay.",
                    client_addr[0],
                    client_addr[1],
                    type(client_info).__name__,
                )
                client_sock.sendall(
                    create_packet(
                        MessageType.HANDSHAKE_REJECT,
                        {
                            "status": "REJECT",
                            "reason": "HELLO_HANDSHAKE payload must be a JSON object.",
                        },
                    )
                )
                return False, None

            client_version = client_info.get("client_version")
            raw_name = client_info.get("client_name", "Unknown-Client")
            client_name = (
                raw_name
                if isinstance(raw_name, str) and raw_name.strip()
                else "Unknown-Client"
            )

            logger.info(
                "[%s:%d] Nhận yêu cầu bắt tay từ client '%s' (Protocol v%s)",
                client_addr[0],
                client_addr[1],
                client_name,
                client_version,
            )

            # Bước 3: Kiểm tra tính tương thích của phiên bản (không chấp nhận bool == 1)
            if isinstance(client_version, bool) or client_version != PROTOCOL_VERSION:
                logger.warning(
                    "[%s:%d] Phiên bản client (%s) không khớp với server (%s). Từ chối bắt tay.",
                    client_addr[0],
                    client_addr[1],
                    client_version,
                    PROTOCOL_VERSION,
                )
                reject_payload = {
                    "status": "REJECT",
                    "reason": f"Protocol version mismatch. Required: {PROTOCOL_VERSION}, Got: {client_version}",
                    "server_version": PROTOCOL_VERSION,
                }
                client_sock.sendall(
                    create_packet(MessageType.HANDSHAKE_REJECT, reject_payload)
                )
                return False, None

            # Bước 4: Đăng ký handler trước khi ACK tới tay client rồi gửi HANDSHAKE_ACK
            if on_ready_before_ack is not None:
                on_ready_before_ack(client_info)

            ack_payload = {
                "status": "OK",
                "server_id": self.server_id,
                "version": PROTOCOL_VERSION,
                "encryption_enabled": self.crypto_key is not None,
                "tracker_key": public_key_text(self._ticket_key),
                "message": f"Welcome to {self.server_id}! Handshake successful.",
            }
            client_sock.sendall(create_packet(MessageType.HANDSHAKE_ACK, ack_payload))

            # Khôi phục blocking mode mặc định sau khi handshake xong
            client_sock.settimeout(None)

            logger.info(
                "✅ [%s:%d] Bắt tay thành công với client '%s'!",
                client_addr[0],
                client_addr[1],
                client_name,
            )
            return True, client_info

        except (socket.timeout, TimeoutError):
            logger.warning(
                "[%s:%d] Quá thời gian chờ bắt tay (Handshake Timeout).",
                client_addr[0],
                client_addr[1],
            )
            return False, None
        except (ConnectionClosedError, ProtocolError, OSError) as exc:
            logger.error(
                "[%s:%d] Lỗi trong quá trình bắt tay: %s",
                client_addr[0],
                client_addr[1],
                exc,
            )
            return False, None
        except Exception as exc:
            logger.error(
                "[%s:%d] Lỗi không mong đợi khi bắt tay: %s",
                client_addr[0],
                client_addr[1],
                exc,
            )
            return False, None

    def register_handler(self, handler: ClientHandler) -> None:
        """Đăng ký một ClientHandler mới vào bộ quản lý (Thread-Safe)."""
        with self._handlers_lock:
            if not self.is_running:
                raise OSError("Server stopped during handshake.")
            self.handlers[handler.client_addr] = handler
            active_count = len(self.handlers)
        logger.info(
            "➕ Đã thêm handler [%s:%d]. Số Client trực tuyến: %d",
            handler.client_addr[0],
            handler.client_addr[1],
            active_count,
        )

    def unregister_handler(self, client_addr: Tuple[str, int]) -> None:
        """Hủy đăng ký một ClientHandler khi kết nối đóng (Thread-Safe)."""
        with self._handlers_lock:
            self.handlers.pop(client_addr, None)
            active_count = len(self.handlers)
        logger.info(
            "➖ Đã gỡ bỏ handler [%s:%d]. Số Client còn lại: %d",
            client_addr[0],
            client_addr[1],
            active_count,
        )

    def get_active_client_count(self) -> int:
        """Lấy số lượng client đang kết nối đồng thời."""
        with self._handlers_lock:
            return len(self.handlers)

    def get_all_handlers(self) -> List[ClientHandler]:
        """Lấy danh sách bản sao các ClientHandler đang hoạt động (Thread-Safe)."""
        with self._handlers_lock:
            return list(self.handlers.values())

    def broadcast_packet(
        self,
        msg_type: MessageType | int,
        payload: Any = b"",
        exclude_addr: Optional[Tuple[str, int]] = None,
        only_authenticated: bool = False,
        flags: int = 0,
    ) -> int:
        """
        Gửi gói tin phát thanh (Broadcast) đến tất cả các Client đang kết nối.

        Args:
            msg_type: Loại thông điệp.
            payload: Dữ liệu cần gửi.
            exclude_addr: Địa chỉ của Client cần loại trừ (ví dụ không gửi lại cho người vừa gửi).
            only_authenticated: Chỉ gửi tới các client đã xác thực đăng nhập nếu True.
            flags: Cờ bitmask gói tin.

        Returns:
            int: Số lượng client gửi thành công.
        """
        with self._broadcast_lock:
            handlers = self.get_all_handlers()
            success_count = 0
            for handler in handlers:
                if exclude_addr and handler.client_addr == exclude_addr:
                    continue
                if only_authenticated and not handler.is_authenticated:
                    continue
                if handler.send_packet(msg_type, payload, flags=flags):
                    success_count += 1
            return success_count

    def issue_peer_ticket(self, sender, recipient):
        if sender is None or not sender.identity_key or not recipient.identity_key:
            raise ValueError("Both peers must register an identity key.")
        claims = {
            "id": uuid.uuid4().hex,
            "sender": sender.username,
            "recipient": recipient.username,
            "sender_session": sender.session_id,
            "recipient_session": recipient.session_id,
            "sender_key": sender.identity_key,
            "recipient_key": recipient.identity_key,
            "expires": time.time() + 30,
        }
        return {"claims": claims, "signature": sign(self._ticket_key, claims)}

    def accept_one(self) -> Tuple[Optional[socket.socket], Optional[Tuple[str, int]]]:
        """
        Chấp nhận một kết nối đơn lẻ và thực hiện bắt tay (Phục vụ kiểm thử).
        """
        if not self.server_sock or not self.is_running:
            raise RuntimeError("Server chưa được khởi động. Hãy gọi start() trước.")

        try:
            client_sock, client_addr = self.server_sock.accept()
            logger.info("⚡ Kết nối TCP mới từ: %s:%d", client_addr[0], client_addr[1])

            success, _info = self.handle_handshake(client_sock, client_addr)
            if success:
                return client_sock, client_addr
            else:
                try:
                    client_sock.close()
                except OSError:
                    pass
                return None, None
        except socket.timeout:
            return None, None
        except OSError as exc:
            if self.is_running:
                logger.error("Lỗi khi accept kết nối: %s", exc)
            return None, None

    def _accept_and_handle_connection(
        self, client_sock: socket.socket, client_addr: Tuple[str, int]
    ) -> None:
        """Thực hiện handshake trên luồng worker (không chặn vòng accept) rồi phục vụ Client."""
        handler_holder: Dict[str, ClientHandler] = {}
        try:

            def _register_before_ack(client_info: dict) -> None:
                h = ClientHandler(
                    client_sock=client_sock,
                    client_addr=client_addr,
                    server=self,
                    client_info=client_info,
                )
                handler_holder["handler"] = h
                self.register_handler(h)

            success, _info = self.handle_handshake(
                client_sock,
                client_addr,
                on_ready_before_ack=_register_before_ack,
            )
        finally:
            with self._handlers_lock:
                self._pending_sockets.discard(client_sock)
            self._handshake_sem.release()

        if not success:
            handler = handler_holder.get("handler")
            if handler is not None:
                handler.close()
            else:
                try:
                    client_sock.close()
                except OSError:
                    pass
            return

        handler = handler_holder["handler"]
        handler.run()

    def serve_forever(self) -> None:
        """
        Vòng lặp lắng nghe chính áp dụng mô hình Thread-per-Client.
        Vòng accept chỉ nhận socket TCP và giao ngay sang worker thread để handshake
        chậm không chặn các client khác.
        """
        if not self.is_running:
            self.start()

        logger.info(
            "🌟 Server đang chạy ở chế độ ĐA NHIỆM (Multi-threading). Sẵn sàng phục vụ nhiều client cùng lúc..."
        )

        try:
            while self.is_running:
                try:
                    # Chấp nhận kết nối TCP từ client mới
                    client_sock, client_addr = self.server_sock.accept()
                except OSError:
                    # Socket server đã bị đóng trong stop()
                    break

                logger.info(
                    "⚡ Chấp nhận kết nối TCP từ %s:%d", client_addr[0], client_addr[1]
                )

                with self._handlers_lock:
                    at_capacity = (
                        len(self.handlers) + len(self._pending_sockets)
                        >= self.MAX_ACTIVE_CONNECTIONS
                    )
                if at_capacity or not self._handshake_sem.acquire(blocking=False):
                    logger.warning(
                        "⚠️ Quá nhiều kết nối đang handshake đồng thời (%d). Từ chối %s:%d.",
                        self.MAX_PENDING_HANDSHAKES,
                        client_addr[0],
                        client_addr[1],
                    )
                    try:
                        client_sock.close()
                    except OSError:
                        pass
                    continue

                with self._handlers_lock:
                    self._pending_sockets.add(client_sock)

                conn_thread = threading.Thread(
                    target=self._accept_and_handle_connection,
                    args=(client_sock, client_addr),
                    name=f"Handler-{client_addr[0]}:{client_addr[1]}",
                    daemon=True,
                )
                conn_thread.start()

        except KeyboardInterrupt:
            logger.info("Nhận tín hiệu dừng từ bàn phím (Ctrl+C).")
        finally:
            self.stop()

    def _run_zombie_cleaner(self) -> None:
        """
        Luồng nền định kỳ rà soát và đóng các kết nối Zombie (Half-Open Sockets).
        Nếu Client bị rớt mạng đột ngột không gửi FIN, sau zombie_timeout giây không có
        Heartbeat Ping thì Server sẽ chủ động đóng socket và dọn dẹp bộ nhớ.
        """
        logger.info(
            "🧟 Luồng ZombieCleaner đã khởi động (Quét mỗi %.1fs, Timeout: %.1fs)...",
            self.zombie_check_interval,
            self.zombie_timeout,
        )
        while not self._stop_zombie_event.is_set() and self.is_running:
            now = time.monotonic()
            handlers = self.get_all_handlers()
            for h in handlers:
                if now - h.last_seen > self.zombie_timeout:
                    logger.warning(
                        "🧟 [ZombieCleaner] Client [%s:%d] ('%s') đã mất kết nối ngầm (Không có heartbeat trong %.1fs). Đóng kết nối...",
                        h.client_addr[0],
                        h.client_addr[1],
                        h.username or h.client_name,
                        now - h.last_seen,
                    )
                    h.close()

            self._stop_zombie_event.wait(timeout=self.zombie_check_interval)
        logger.info("🛑 Luồng ZombieCleaner đã dừng.")

    def stop(self) -> None:
        """
        Đóng socket server và dọn dẹp toàn bộ các luồng Client đang kết nối.
        """
        with self._lock:
            if not self.is_running and self.server_sock is None:
                return
            self.is_running = False
            if self._discovery is not None:
                self._discovery.close()
                self._discovery = None

            # Dừng luồng ZombieCleaner
            self._stop_zombie_event.set()

            # 1. Đóng toàn bộ socket đang chờ handshake và ClientHandler đang hoạt động
            with self._handlers_lock:
                pending_socks = list(self._pending_sockets)
                self._pending_sockets.clear()
                active_handlers = list(self.handlers.values())
                self.handlers.clear()

            for psock in pending_socks:
                try:
                    try:
                        psock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    psock.close()
                except OSError:
                    pass

            # Xóa sạch phiên người dùng
            self.session_mgr.clear()

            logger.info("Đang đóng toàn bộ %d kết nối Client...", len(active_handlers))
            for handler in active_handlers:
                handler.close()

            # 2. Đóng Server socket chính
            if self.server_sock:
                try:
                    try:
                        self.server_sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    self.server_sock.close()
                    logger.info("🛑 Đã đóng Server socket thành công.")
                except OSError as exc:
                    logger.warning("Lỗi khi đóng server socket: %s", exc)
                finally:
                    self.server_sock = None
