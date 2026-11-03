"""
Module: client.client_core
Mô tả: Lớp Client chính quản lý TCP Socket áp dụng kiến trúc 2 luồng đồng thời:
  - Luồng 1 (Main/Sender Thread): Thực hiện kết nối, gửi lệnh, tin nhắn và file.
  - Luồng 2 (Receiver Thread): Chạy ngầm liên tục lắng nghe và xử lý gói tin từ Server trả về.
"""

from __future__ import annotations

import os
import queue
import socket
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from common.crypto_utils import derive_key
from common.logger import get_logger
from common.message_types import MessageType
from common.protocol import (
    PROTOCOL_VERSION,
    ConnectionClosedError,
    Packet,
    ProtocolError,
    create_packet,
    recv_packet,
)
from client.file_transfer import (
    DEFAULT_CHUNK_SIZE,
    IncomingFileTransfer,
    calculate_file_hash,
    pack_chunk_payload,
    read_file_chunks,
    unpack_chunk_payload,
)
from client.heartbeat import HeartbeatSender

logger = get_logger("client.core")


class ClientCore:
    """
    Lớp quản lý Client TCP đa luồng (Dual-thread architecture).
    
    Cấu trúc luồng:
      1. Main Thread / UI Thread: Gọi connect(), send_packet(), disconnect().
      2. Receiver Thread (Background Daemon): Lặp recv_packet() để đón nhận
         tin nhắn, thông báo, file chunks mà không làm đơ giao diện người dùng.
    """

    DEFAULT_HOST: str = "127.0.0.1"
    DEFAULT_PORT: int = 9000

    def __init__(
        self,
        server_host: str = DEFAULT_HOST,
        server_port: int = DEFAULT_PORT,
        client_name: str = "Client-App",
    ) -> None:
        self.server_host = server_host
        self.server_port = server_port
        self.client_name = client_name
        self.sock: Optional[socket.socket] = None
        self.is_connected: bool = False
        self.server_info: Optional[Dict[str, Any]] = None

        # Khóa bảo vệ khi gửi dữ liệu từ nhiều luồng (Thread-Safe Send)
        self._send_lock = threading.Lock()

        # Luồng lắng nghe ngầm
        self._receiver_thread: Optional[threading.Thread] = None

        # Hàng đợi chứa các gói tin nhận về (phục vụ GUI và Test)
        self.received_queue: queue.Queue[Packet] = queue.Queue()

        # Callbacks cho từng loại mã thông điệp: Dict[MessageType, List[Callable]]
        self._packet_callbacks: Dict[int, List[Callable[[Packet], None]]] = {}

        # Callback chung cho tất cả các gói tin đến
        self.on_packet_received: Optional[Callable[[Packet], None]] = None

        # Trạng thái xác thực & Danh tính người dùng
        self.username: Optional[str] = None
        self.is_authenticated: bool = False
        self.online_users: List[str] = []

        # Cơ chế đồng bộ phản hồi xác thực & danh sách người dùng
        self._auth_event = threading.Event()
        self._auth_result: Tuple[bool, str] = (False, "")
        self._user_list_event = threading.Event()
        self._user_list_result: Optional[List[str]] = None

        # Đăng ký các callback nội bộ xử lý trạng thái
        self.register_callback(MessageType.AUTH_RESP_SUCCESS, self._handle_auth_success)
        self.register_callback(MessageType.AUTH_RESP_FAIL, self._handle_auth_fail)
        self.register_callback(MessageType.USER_LIST_RESP, self._handle_user_list_resp)
        self.register_callback(MessageType.USER_STATUS_BROADCAST, self._handle_user_status_broadcast)

        # Quản lý truyền và nhận file tin cậy
        self.incoming_files: Dict[str, IncomingFileTransfer] = {}
        self.download_dir: str = os.path.join("storage", "client_downloads")
        self.auto_accept_files: bool = True
        self._file_events: Dict[str, threading.Event] = {}
        self._file_results: Dict[str, dict] = {}
        self.on_file_progress: Optional[Callable[[str, int, int, float], None]] = None
        self.on_file_received: Optional[Callable[[str, str, str], None]] = None

        self.register_callback(MessageType.FILE_OFFER_REQ, self._handle_file_offer_req)
        self.register_callback(MessageType.FILE_OFFER_RESP, self._handle_file_offer_resp)
        self.register_callback(MessageType.FILE_CHUNK, self._handle_file_chunk)
        self.register_callback(MessageType.FILE_ACK, self._handle_file_ack)

        # Quản lý luồng gửi nhịp tim (Heartbeat / Keepalive)
        self.heartbeat_sender: Optional[HeartbeatSender] = None
        self.heartbeat_interval: float = 4.0

        # Lớp mã hóa bảo mật (AES-Fernet)
        self.crypto_key: Optional[bytes] = None

    def enable_encryption(self, passphrase: Optional[str] = None) -> None:
        """Kích hoạt mã hóa đối xứng AES cho toàn bộ payload gửi đi."""
        self.crypto_key = derive_key(passphrase) if passphrase else derive_key()
        logger.info("🔒 Đã kích hoạt lớp mã hóa AES cho Client.")

    def disable_encryption(self) -> None:
        """Tắt mã hóa payload."""
        self.crypto_key = None
        logger.info("🔓 Đã tắt lớp mã hóa AES.")

    def register_callback(
        self, msg_type: MessageType | int, callback: Callable[[Packet], None]
    ) -> None:
        """Đăng ký hàm callback xử lý khi nhận được loại gói tin cụ thể."""
        msg_key = int(msg_type)
        if msg_key not in self._packet_callbacks:
            self._packet_callbacks[msg_key] = []
        self._packet_callbacks[msg_key].append(callback)

    def connect(
        self,
        timeout: float = 5.0,
        protocol_version: int = PROTOCOL_VERSION,
        start_receiver: bool = True,
        start_heartbeat: bool = True,
    ) -> bool:
        """
        Kết nối tới Server TCP, thực hiện bắt tay và khởi chạy luồng lắng nghe nền.

        Args:
            timeout: Thời gian tối đa chờ kết nối (giây).
            protocol_version: Phiên bản giao thức gửi đi (mặc định là PROTOCOL_VERSION).
            start_receiver: Có tự động bật Receiver Thread chạy nền hay không (mặc định True).

        Returns:
            bool: True nếu kết nối và bắt tay thành công, False nếu thất bại.
        """
        if self.is_connected:
            logger.warning("Client đã kết nối sẵn tới %s:%d.", self.server_host, self.server_port)
            return True

        logger.info(
            "Đang kết nối tới Server %s:%d (Timeout: %.1fs)...",
            self.server_host,
            self.server_port,
            timeout,
        )

        try:
            # 1. Tạo socket TCP IPv4
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)

            # 2. Thực hiện 3-way handshake TCP
            self.sock.connect((self.server_host, self.server_port))
            logger.info("🔗 Đã thiết lập kết nối TCP thành công với %s:%d.", self.server_host, self.server_port)

            # 3. Thực hiện bắt tay tầng ứng dụng (Application Layer Handshake)
            handshake_success = self._perform_handshake(protocol_version=protocol_version)
            if handshake_success:
                self.is_connected = True
                # Bỏ timeout để socket hoạt động ở chế độ bình thường
                self.sock.settimeout(None)

                # 4. Kích hoạt Luồng 2 (Receiver Thread) chạy nền nếu được yêu cầu
                if start_receiver:
                    self._start_receiver()

                # 5. Kích hoạt Luồng Heartbeat định kỳ gửi PING duy trì kết nối
                if start_heartbeat:
                    self.heartbeat_sender = HeartbeatSender(self, interval_seconds=self.heartbeat_interval)
                    self.heartbeat_sender.start()

                return True
            else:
                self.disconnect()
                return False

        except ConnectionRefusedError:
            logger.error(
                "❌ Kết nối bị từ chối: Không thể kết nối tới Server tại %s:%d. Hãy chắc chắn Server đã được khởi động.",
                self.server_host,
                self.server_port,
            )
            self._cleanup_socket()
            raise
        except socket.timeout:
            logger.error(
                "❌ Hết thời gian chờ kết nối (Timeout) tới Server %s:%d.",
                self.server_host,
                self.server_port,
            )
            self._cleanup_socket()
            raise
        except OSError as exc:
            logger.error("❌ Lỗi mạng khi kết nối: %s", exc)
            self._cleanup_socket()
            return False

    def _perform_handshake(self, protocol_version: int = PROTOCOL_VERSION) -> bool:
        """Thực hiện trao đổi gói tin HELLO_HANDSHAKE và HANDSHAKE_ACK."""
        if not self.sock:
            return False

        try:
            logger.info(
                "Đang gửi HELLO_HANDSHAKE (Client: '%s', Protocol v%d)...",
                self.client_name,
                protocol_version,
            )

            hello_payload = {
                "client_name": self.client_name,
                "client_version": protocol_version,
            }
            packet = create_packet(
                MessageType.HELLO_HANDSHAKE,
                hello_payload,
                version=protocol_version,
            )
            self.sock.sendall(packet)

            response = recv_packet(self.sock)

            if response.msg_type == MessageType.HANDSHAKE_ACK:
                self.server_info = response.to_json()
                logger.info(
                    "✅ Bắt tay ứng dụng THÀNH CÔNG! Server ID: '%s' | Thông điệp: '%s'",
                    self.server_info.get("server_id"),
                    self.server_info.get("message"),
                )
                return True

            elif response.msg_type == MessageType.HANDSHAKE_REJECT:
                reject_info = response.to_json()
                logger.warning(
                    "⛔ Bắt tay ứng dụng BỊ TỪ CHỐI bởi Server! Lý do: %s",
                    reject_info.get("reason", "Không rõ nguyên nhân"),
                )
                return False

            else:
                logger.error(
                    "❌ Nhận gói tin không mong muốn trong quá trình bắt tay: %s",
                    response.msg_type,
                )
                return False

        except (ConnectionClosedError, ProtocolError, OSError) as exc:
            logger.error("❌ Lỗi xảy ra trong quá trình trao đổi Handshake: %s", exc)
            return False

    def _start_receiver(self) -> None:
        """Khởi chạy Luồng lắng nghe ngầm (Receiver Thread)."""
        self._receiver_thread = threading.Thread(
            target=self._receiver_loop,
            name=f"ClientRecv-{self.client_name}",
            daemon=True,
        )
        self._receiver_thread.start()
        logger.info("🎧 Receiver Thread đã khởi động và đang lắng nghe phản hồi từ Server...")

    def _receiver_loop(self) -> None:
        """
        Vòng lặp chạy trong Receiver Thread:
        Đọc liên tục các gói tin từ Server trả về và phân phát cho callbacks / queue.
        """
        while self.is_connected and self.sock:
            try:
                packet = recv_packet(self.sock, decrypt_key=self.crypto_key)
                # Đưa vào queue để GUI / Caller có thể lấy ra
                self.received_queue.put(packet)

                # Gọi callback chung nếu có
                if self.on_packet_received:
                    try:
                        self.on_packet_received(packet)
                    except Exception as e:
                        logger.error("Lỗi trong on_packet_received callback: %s", e)

                # Gọi các callback chuyên biệt theo msg_type
                msg_key = int(packet.msg_type)
                if msg_key in self._packet_callbacks:
                    for cb in self._packet_callbacks[msg_key]:
                        try:
                            cb(packet)
                        except Exception as e:
                            logger.error("Lỗi trong packet callback [%s]: %s", msg_key, e)

            except ConnectionClosedError:
                if self.is_connected:
                    logger.warning("🔌 Server đã ngắt kết nối.")
                break
            except (ConnectionResetError, ConnectionAbortedError):
                if self.is_connected:
                    logger.warning("⚠️ Kết nối tới Server bị reset đột ngột.")
                break
            except OSError:
                # Socket có thể đã được close bởi disconnect()
                break
            except Exception as exc:
                if self.is_connected:
                    logger.error("❌ Lỗi không mong muốn trong Receiver Loop: %s", exc)
                break

        self.is_connected = False

    def send_packet(
        self,
        msg_type: MessageType | int,
        payload: Any = b"",
        flags: int = 0,
    ) -> bool:
        """
        Gửi một gói tin đến Server an toàn đa luồng (Thread-Safe).
        """
        if not self.is_connected or not self.sock:
            logger.error("Không thể gửi: Socket chưa kết nối.")
            return False

        try:
            # Chỉ mã hóa các gói tin nội dung dữ liệu (Data Plane: CHAT, FILE)
            # Giữ nguyên các gói tin điều khiển (Control Plane: AUTH, HANDSHAKE, USER_LIST, PING)
            encrypt_target = (
                self.crypto_key is not None
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
                encrypt_key=self.crypto_key if encrypt_target else None,
            )
            with self._send_lock:
                if self.sock:
                    self.sock.sendall(packet_bytes)
            return True
        except (OSError, ConnectionError) as exc:
            logger.error("Lỗi khi gửi gói tin lên Server: %s", exc)
            self.is_connected = False
            return False

    # ==========================================================================
    # CÁC HÀM XỬ LÝ SỰ KIỆN NỘI BỘ (INTERNAL EVENT HANDLERS)
    # ==========================================================================
    def _handle_auth_success(self, packet: Packet) -> None:
        """Xử lý khi nhận được phản hồi đăng nhập thành công."""
        try:
            data = packet.to_json()
        except Exception:
            data = {}
        self.is_authenticated = True
        self.username = data.get("username", self.client_name)
        self.client_name = self.username
        self.online_users = data.get("online_users", [self.username])
        self._auth_result = (True, data.get("message", "Đăng nhập thành công."))
        self._auth_event.set()
        logger.info("🎉 Đã xác thực thành công danh tính: '%s'", self.username)

    def _handle_auth_fail(self, packet: Packet) -> None:
        """Xử lý khi Server từ chối đăng nhập."""
        try:
            data = packet.to_json()
            reason = data.get("reason", "Đăng nhập thất bại.")
        except Exception:
            reason = packet.to_text() or "Đăng nhập thất bại."
        self.is_authenticated = False
        self._auth_result = (False, reason)
        self._auth_event.set()
        logger.warning("⛔ Đăng nhập bị từ chối: %s", reason)

    def _handle_user_list_resp(self, packet: Packet) -> None:
        """Xử lý danh sách user từ Server trả về."""
        try:
            data = packet.to_json()
            users = data.get("users", [])
        except Exception:
            users = []
        self.online_users = users
        self._user_list_result = users
        self._user_list_event.set()

    def _handle_user_status_broadcast(self, packet: Packet) -> None:
        """Cập nhật danh sách online khi có thông báo người dùng JOINED / LEFT."""
        try:
            data = packet.to_json()
            event = data.get("event")
            user = data.get("username")
            if event == "JOINED" and user:
                if user not in self.online_users:
                    self.online_users.append(user)
                logger.info("👤 [%s] vừa tham gia hệ thống.", user)
            elif event == "LEFT" and user:
                if user in self.online_users:
                    self.online_users.remove(user)
                logger.info("👤 [%s] vừa rời hệ thống.", user)
        except Exception as e:
            logger.error("Lỗi khi xử lý USER_STATUS_BROADCAST: %s", e)

    def _handle_file_offer_req(self, packet: Packet) -> None:
        """Xử lý khi nhận được đề nghị gửi file (FILE_OFFER_REQ) từ người khác."""
        try:
            offer = packet.to_json()
            file_id = offer["file_id"]
            sender = offer["sender"]
            file_name = offer["file_name"]
            file_size = offer["file_size"]
            total_chunks = offer["total_chunks"]
            expected_sha256 = offer["sha256"]

            logger.info("📥 Nhận đề xuất gửi file '%s' (%s bytes, %d chunks) từ '%s'.", file_name, file_size, total_chunks, sender)

            if self.auto_accept_files:
                os.makedirs(self.download_dir, exist_ok=True)
                save_path = os.path.join(self.download_dir, file_name)
                transfer = IncomingFileTransfer(
                    file_id=file_id,
                    sender=sender,
                    file_name=file_name,
                    file_size=file_size,
                    total_chunks=total_chunks,
                    expected_sha256=expected_sha256,
                    save_path=save_path,
                )
                self.incoming_files[file_id] = transfer

                resp = {
                    "file_id": file_id,
                    "sender": sender,
                    "recipient": self.username or self.client_name,
                    "status": "ACCEPTED",
                }
                self.send_packet(MessageType.FILE_OFFER_RESP, resp)
                logger.info("✅ Đã đồng ý nhận file '%s'.", file_name)
            else:
                resp = {
                    "file_id": file_id,
                    "sender": sender,
                    "recipient": self.username or self.client_name,
                    "status": "REJECTED",
                    "reason": "Người nhận từ chối nhận file.",
                }
                self.send_packet(MessageType.FILE_OFFER_RESP, resp)
        except Exception as e:
            logger.error("Lỗi xử lý FILE_OFFER_REQ: %s", e)

    def _handle_file_offer_resp(self, packet: Packet) -> None:
        """Xử lý phản hồi chấp nhận/từ chối từ người nhận (FILE_OFFER_RESP)."""
        try:
            resp = packet.to_json()
            file_id = resp.get("file_id")
            if file_id and file_id in self._file_events:
                self._file_results[file_id] = resp
                self._file_events[file_id].set()
        except Exception as e:
            logger.error("Lỗi xử lý FILE_OFFER_RESP: %s", e)

    def _handle_file_chunk(self, packet: Packet) -> None:
        """Xử lý khi nhận được một chunk dữ liệu nhị phân của file (FILE_CHUNK)."""
        try:
            meta, chunk_data = unpack_chunk_payload(packet.payload)
            file_id = meta["file_id"]
            chunk_index = meta["chunk_index"]

            transfer = self.incoming_files.get(file_id)
            if not transfer:
                logger.warning("Nhận chunk cho file_id không tồn tại: %s", file_id)
                return

            is_finished = transfer.add_chunk(chunk_index, chunk_data)

            if self.on_file_progress:
                try:
                    self.on_file_progress(
                        file_id,
                        len(transfer.received_chunks),
                        transfer.total_chunks,
                        transfer.progress_percentage,
                    )
                except Exception:
                    pass

            if is_finished:
                ok, reason = transfer.assemble_and_verify()
                ack_payload = {
                    "file_id": file_id,
                    "sender": transfer.sender,
                    "recipient": self.username or self.client_name,
                    "status": "SUCCESS" if ok else "FAILED",
                    "reason": reason,
                    "file_name": transfer.file_name,
                    "save_path": transfer.save_path,
                }
                self.send_packet(MessageType.FILE_ACK, ack_payload)

                if ok and self.on_file_received:
                    try:
                        self.on_file_received(transfer.sender, transfer.file_name, transfer.save_path)
                    except Exception as e:
                        logger.error("Lỗi callback on_file_received: %s", e)
        except Exception as e:
            logger.error("Lỗi xử lý FILE_CHUNK: %s", e)

    def _handle_file_ack(self, packet: Packet) -> None:
        """Xử lý khi nhận được xác nhận nhận file (FILE_ACK)."""
        try:
            ack = packet.to_json()
            file_id = ack.get("file_id")
            if file_id and file_id in self._file_events:
                self._file_results[file_id] = ack
                self._file_events[file_id].set()
        except Exception as e:
            logger.error("Lỗi xử lý FILE_ACK: %s", e)

    # ==========================================================================
    # CÁC TIỆN ÍCH NGHIỆP VỤ (PUBLIC API)
    # ==========================================================================
    def authenticate(self, username: str, timeout: float = 5.0) -> Tuple[bool, str]:
        """
        Gửi yêu cầu đăng nhập và chờ phản hồi từ Server.

        Args:
            username: Tên người dùng muốn đăng ký.
            timeout: Thời gian chờ phản hồi tối đa (giây).

        Returns:
            Tuple[bool, str]: (Thành công hay không, Lý do / Tin nhắn).
        """
        if not self.is_connected:
            return False, "Chưa kết nối tới server."

        self._auth_event.clear()
        self._auth_result = (False, "Timeout")

        success = self.send_packet(MessageType.AUTH_REQ, {"username": username})
        if not success:
            return False, "Không thể gửi gói tin AUTH_REQ."

        if self._auth_event.wait(timeout=timeout):
            return self._auth_result

        return False, "Quá thời gian chờ phản hồi xác thực từ server."

    def request_user_list(self, timeout: float = 5.0) -> Optional[List[str]]:
        """
        Yêu cầu lấy danh sách người dùng đang online từ Server.

        Args:
            timeout: Thời gian chờ phản hồi (giây).

        Returns:
            Optional[List[str]]: Danh sách username hoặc None nếu thất bại.
        """
        if not self.is_connected:
            return None

        self._user_list_event.clear()
        self._user_list_result = None

        success = self.send_packet(MessageType.USER_LIST_REQ, {})
        if not success:
            return None

        if self._user_list_event.wait(timeout=timeout):
            return self._user_list_result

        return None

    def send_broadcast(self, content: str) -> bool:
        """
        Gửi tin nhắn phát thanh tới toàn bộ phòng chat chung.
        """
        sender_name = self.username if self.username else self.client_name
        return self.send_packet(
            MessageType.CHAT_BROADCAST,
            {
                "sender": sender_name,
                "content": content,
                "text": content,
                "timestamp": time.time(),
            },
        )

    def send_chat(self, text: str) -> bool:
        """Tiện ích gửi tin nhắn trò chuyện lên phòng chat chung (alias cho send_broadcast)."""
        return self.send_broadcast(text)

    def send_direct_message(self, recipient: str, content: str) -> bool:
        """
        Gửi tin nhắn riêng 1-1 (Private Message / Unicast) tới một người dùng cụ thể.

        Args:
            recipient: Tên người nhận.
            content: Nội dung tin nhắn.

        Returns:
            bool: True nếu gói tin gửi thành công lên server.
        """
        sender_name = self.username if self.username else self.client_name
        return self.send_packet(
            MessageType.CHAT_DIRECT,
            {
                "sender": sender_name,
                "recipient": recipient,
                "content": content,
                "timestamp": time.time(),
            },
        )

    def send_file(
        self,
        recipient: str,
        file_path: str,
        progress_callback: Optional[Callable[[int, int, float], None]] = None,
        timeout: float = 30.0,
    ) -> Tuple[bool, str]:
        """
        Gửi một file cho người dùng khác qua cơ chế cắt nhỏ (Chunking) và kiểm tra SHA-256.

        Args:
            recipient: Tên người nhận.
            file_path: Đường dẫn tới file cần gửi.
            progress_callback: Hàm callback nhận (chunks_sent, total_chunks, percent).
            timeout: Thời gian tối đa chờ phản hồi.

        Returns:
            Tuple[bool, str]: (Thành công hay không, Thông báo kết quả).
        """
        if not self.is_connected:
            return False, "Chưa kết nối tới Server."

        from pathlib import Path
        path = Path(file_path)
        if not path.is_file():
            return False, f"File không tồn tại: {file_path}"

        file_size = path.stat().st_size
        total_chunks = (file_size + DEFAULT_CHUNK_SIZE - 1) // DEFAULT_CHUNK_SIZE
        if total_chunks == 0:
            total_chunks = 1

        sha256 = calculate_file_hash(path)
        file_id = str(uuid.uuid4())[:8]

        # 1. Gửi FILE_OFFER_REQ
        offer_event = threading.Event()
        self._file_events[file_id] = offer_event

        offer_payload = {
            "file_id": file_id,
            "sender": self.username or self.client_name,
            "recipient": recipient,
            "file_name": path.name,
            "file_size": file_size,
            "total_chunks": total_chunks,
            "sha256": sha256,
        }
        logger.info(
            "Đang đề xuất gửi file '%s' (%s bytes, %d chunks) cho '%s'...",
            path.name,
            file_size,
            total_chunks,
            recipient,
        )
        self.send_packet(MessageType.FILE_OFFER_REQ, offer_payload)

        # Chờ người nhận phản hồi
        if not offer_event.wait(timeout=timeout):
            self._file_events.pop(file_id, None)
            return False, "Quá thời gian chờ người nhận phản hồi đề nghị gửi file."

        offer_resp = self._file_results.pop(file_id, {})
        if offer_resp.get("status") != "ACCEPTED":
            self._file_events.pop(file_id, None)
            reason = offer_resp.get("reason", "Người nhận từ chối nhận file.")
            return False, reason

        logger.info("Người nhận '%s' đã đồng ý! Bắt đầu truyền %d chunks...", recipient, total_chunks)

        # 2. Truyền từng chunk
        ack_event = threading.Event()
        self._file_events[file_id] = ack_event

        sent_chunks = 0
        for chunk_index, chunk_data in read_file_chunks(path, chunk_size=DEFAULT_CHUNK_SIZE):
            chunk_payload = pack_chunk_payload(
                file_id=file_id,
                chunk_index=chunk_index,
                total_chunks=total_chunks,
                chunk_data=chunk_data,
            )
            self.send_packet(MessageType.FILE_CHUNK, chunk_payload)
            sent_chunks += 1

            percent = (sent_chunks / total_chunks) * 100.0
            if progress_callback:
                try:
                    progress_callback(sent_chunks, total_chunks, percent)
                except Exception:
                    pass

        logger.info("Đã gửi xong %d/%d chunks. Đang chờ xác nhận SHA-256 từ người nhận...", sent_chunks, total_chunks)

        # 3. Chờ FILE_ACK
        if not ack_event.wait(timeout=timeout):
            self._file_events.pop(file_id, None)
            return False, "Quá thời gian chờ xác nhận FILE_ACK từ người nhận."

        self._file_events.pop(file_id, None)
        ack_resp = self._file_results.pop(file_id, {})
        if ack_resp.get("status") == "SUCCESS":
            return True, f"File '{path.name}' đã gửi thành công và xác thực toàn vẹn 100% (SHA-256 khớp)."
        else:
            return False, f"Xác thực file thất bại tại người nhận: {ack_resp.get('reason')}"

    def send_heartbeat(self) -> bool:
        """Tiện ích gửi gói tin kiểm tra nhịp tim (PING) lên Server."""
        return self.send_packet(
            MessageType.HEARTBEAT_PING,
            {"client": self.client_name},
        )

    def disconnect(self, send_notice: bool = True) -> None:
        """
        Chủ động ngắt kết nối với Server (Graceful Disconnect).
        """
        if not self.is_connected and not self.sock:
            return

        logger.info("Đang ngắt kết nối tới Server...")
        if self.sock and self.is_connected and send_notice:
            try:
                disconnect_packet = create_packet(
                    MessageType.DISCONNECT_NOTICE,
                    {"reason": "Client graceful shutdown"},
                )
                with self._send_lock:
                    self.sock.sendall(disconnect_packet)
                    try:
                        # Báo hiệu đã gửi xong dữ liệu (TCP FIN segment) trước khi đóng socket hoàn toàn
                        self.sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            except OSError:
                pass

        self.is_connected = False
        self.is_authenticated = False
        self.username = None
        self.online_users = []

        # Dừng luồng Heartbeat nếu đang chạy
        if self.heartbeat_sender:
            self.heartbeat_sender.stop()
            self.heartbeat_sender = None

        self._cleanup_socket()

        # Chờ Receiver thread kết thúc
        if self._receiver_thread and threading.current_thread() != self._receiver_thread:
            self._receiver_thread.join(timeout=1.0)
            self._receiver_thread = None

        logger.info("🔌 Đã ngắt kết nối hoàn tất.")

    def _cleanup_socket(self) -> None:
        """Dọn dẹp và đóng socket an toàn."""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            finally:
                self.sock = None
