"""
Module: client.client_core
Mô tả: Lớp Client chính quản lý kiến trúc lai Client-Server + P2P File Transfer:
  - Luồng 1 (Main/Sender Thread): Kết nối Tracker/Chat Server, gửi lệnh, tin nhắn và khởi tạo kết nối P2P gửi file.
  - Luồng 2 (Receiver Thread): Lắng nghe nền các gói tin Control Plane & Chat từ Server.
  - Luồng 3 (P2P Listener & Worker Threads): Lắng nghe TCP trực tiếp nhận file từ các Peer khác.
"""

from __future__ import annotations

import json
import os
import queue
import socket
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.fernet import InvalidToken

from common.crypto_utils import decrypt_payload, derive_key, encrypt_payload
from common.logger import get_logger
from common.message_types import MessageType
from common.protocol import (
    FLAG_ENCRYPTED,
    FLAG_NONE,
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
        p2p_port: int = 0,
        p2p_host: Optional[str] = None,
    ) -> None:
        self.server_host = server_host
        self.server_port = server_port
        self.client_name = client_name
        self.sock: Optional[socket.socket] = None
        self.is_connected: bool = False
        self.server_info: Optional[Dict[str, Any]] = None

        # Khóa bảo vệ khi gửi dữ liệu từ nhiều luồng (Thread-Safe Send)
        self._send_lock = threading.Lock()

        # Luồng lắng nghe ngầm từ Server
        self._receiver_thread: Optional[threading.Thread] = None

        # Cấu hình & Listener P2P (Truyền file trực tiếp không qua Server)
        self._configured_p2p_port: int = int(p2p_port)
        self.p2p_host: Optional[str] = p2p_host
        self.p2p_port: Optional[int] = None
        self._p2p_server_sock: Optional[socket.socket] = None
        self._p2p_accept_thread: Optional[threading.Thread] = None
        self._p2p_worker_threads: List[threading.Thread] = []
        self._p2p_workers_lock = threading.Lock()
        self._p2p_running: bool = False

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

        # Cơ chế đồng bộ phản hồi xác thực, danh sách user & tra cứu P2P từ Tracker
        self._auth_event = threading.Event()
        self._auth_result: Tuple[bool, str] = (False, "")
        self._user_list_event = threading.Event()
        self._user_list_result: Optional[List[str]] = None
        self.peer_directory: Dict[str, Dict[str, Any]] = {}
        self._peer_dir_lock = threading.Lock()
        self._lookup_events: Dict[str, threading.Event] = {}
        self._lookup_results: Dict[str, Dict[str, Any]] = {}
        self._lookup_lock = threading.Lock()

        # Đăng ký các callback nội bộ xử lý Control Plane
        self.register_callback(MessageType.AUTH_RESP_SUCCESS, self._handle_auth_success)
        self.register_callback(MessageType.AUTH_RESP_FAIL, self._handle_auth_fail)
        self.register_callback(MessageType.USER_LIST_RESP, self._handle_user_list_resp)
        self.register_callback(MessageType.USER_STATUS_BROADCAST, self._handle_user_status_broadcast)
        self.register_callback(MessageType.PEER_LOOKUP_RESP, self._handle_peer_lookup_resp)

        # Quản lý truyền và nhận file P2P tin cậy
        self.incoming_files: Dict[str, IncomingFileTransfer] = {}
        self._incoming_files_lock = threading.Lock()
        self.download_dir: str = os.path.join("storage", "client_downloads")
        self.auto_accept_files: bool = True
        self.on_file_progress: Optional[Callable[[str, int, int, float], None]] = None
        self.on_file_received: Optional[Callable[[str, str, str], None]] = None
        self.on_file_error: Optional[Callable[[str, str, str], None]] = None
        self.on_disconnected: Optional[Callable[[str], None]] = None

        # Quản lý luồng gửi nhịp tim (Heartbeat / Keepalive)
        self.heartbeat_sender: Optional[HeartbeatSender] = None
        self.heartbeat_interval: float = 4.0

        # Lớp mã hóa bảo mật (AES-Fernet)
        self.crypto_key: Optional[bytes] = None

    @property
    def server_encryption_enabled(self) -> bool:
        """Kiểm tra xem Server có đang bật lớp mã hóa hay chỉ là relay trung gian."""
        return bool((self.server_info or {}).get("encryption_enabled", False))

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
        start_p2p: bool = True,
    ) -> bool:
        """
        Kết nối tới Server TCP, thực hiện bắt tay, mở cổng P2P Listener và khởi chạy luồng nền.

        Args:
            timeout: Thời gian tối đa chờ kết nối (giây).
            protocol_version: Phiên bản giao thức gửi đi (mặc định là PROTOCOL_VERSION).
            start_receiver: Có tự động bật Receiver Thread chạy nền hay không (mặc định True).
            start_heartbeat: Có tự động bật Heartbeat Thread hay không (mặc định True).
            start_p2p: Có tự động mở cổng P2P TCP Listener hay không (mặc định True).

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

                # 4. Mở cổng P2P Listener trước khi authenticate để đăng ký IP:P2P_Port lên Tracker
                if start_p2p:
                    try:
                        self.start_p2p_listener()
                    except OSError as p2p_exc:
                        logger.error("❌ Không thể mở cổng P2P Listener (%s): %s", self._configured_p2p_port, p2p_exc)
                        self.disconnect(send_notice=False)
                        return False

                # 5. Kích hoạt Luồng 2 (Receiver Thread) chạy nền nếu được yêu cầu
                if start_receiver:
                    self._start_receiver()

                # 6. Kích hoạt Luồng Heartbeat định kỳ gửi PING duy trì kết nối
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

    def _unwrap_incoming_packet(self, packet: Packet) -> Tuple[Optional[Packet], Optional[str]]:
        """
        Giải mã gói tin đến một cách an toàn:
          1. Nếu có cờ FLAG_ENCRYPTED: giải mã bằng self.crypto_key.
          2. Nếu là CHAT_DIRECT dạng E2EE envelope: giải mã trường ciphertext.
        Trả về (Packet đã giải mã, None) hoặc (None, thông báo lỗi) nếu sai/thiếu khóa.
        """
        if packet.is_encrypted:
            if not self.crypto_key:
                return None, "Nhận được dữ liệu mã hóa AES nhưng bạn chưa nhập mật khẩu phòng."
            try:
                return packet.get_decrypted_packet(self.crypto_key), None
            except InvalidToken:
                return None, "Không thể giải mã dữ liệu AES (mật khẩu phòng không khớp với người gửi)."

        if int(packet.msg_type) == int(MessageType.CHAT_DIRECT):
            try:
                data = packet.to_json()
                if isinstance(data, dict) and data.get("e2ee") and "ciphertext" in data:
                    sender_name = data.get("sender", "Ẩn danh")
                    if not self.crypto_key:
                        return None, f"Tin nhắn riêng từ '{sender_name}' được mã hóa AES, nhưng bạn chưa nhập mật khẩu phòng."
                    plain_bytes = decrypt_payload(str(data["ciphertext"]).encode("ascii"), self.crypto_key)
                    inner = json.loads(plain_bytes.decode("utf-8"))
                    unwrapped_payload = {
                        "sender": data.get("sender") or inner.get("sender", sender_name),
                        "recipient": data.get("recipient") or inner.get("recipient", ""),
                        "content": inner.get("content", ""),
                        "timestamp": data.get("timestamp") or inner.get("timestamp"),
                        "type": "direct",
                    }
                    return Packet(
                        msg_type=MessageType.CHAT_DIRECT,
                        payload=json.dumps(unwrapped_payload, ensure_ascii=False).encode("utf-8"),
                        flags=FLAG_NONE,
                        version=packet.version,
                    ), None
            except InvalidToken:
                return None, "Không thể giải mã tin nhắn riêng AES (mật khẩu phòng không khớp)."
            except Exception as exc:
                logger.warning("Lỗi giải mã phong bì E2EE CHAT_DIRECT: %s", exc)
                return None, "Không thể giải mã nội dung tin nhắn riêng E2EE."

        return packet, None

    def _dispatch_received_packet(self, packet: Packet) -> None:
        """Đưa gói tin vào queue và kích hoạt các callbacks đã đăng ký."""
        self.received_queue.put(packet)

        if self.on_packet_received:
            try:
                self.on_packet_received(packet)
            except Exception as e:
                logger.error("Lỗi trong on_packet_received callback: %s", e)

        msg_key = int(packet.msg_type)
        if msg_key in self._packet_callbacks:
            for cb in self._packet_callbacks[msg_key]:
                try:
                    cb(packet)
                except Exception as e:
                    logger.error("Lỗi trong packet callback [%s]: %s", msg_key, e)

    def _receiver_loop(self) -> None:
        """
        Vòng lặp chạy trong Receiver Thread:
        Đọc liên tục các gói tin từ Server trả về và phân phát cho callbacks / queue.
        """
        disconnect_reason: Optional[str] = None
        while self.is_connected and self.sock:
            try:
                raw_packet = recv_packet(self.sock)
                packet, decrypt_err = self._unwrap_incoming_packet(raw_packet)

                if decrypt_err:
                    logger.warning("🔒 %s", decrypt_err)
                    err_packet = Packet(
                        msg_type=MessageType.ERROR_NOTICE,
                        payload=json.dumps(
                            {"code": "DECRYPTION_FAILED", "message": decrypt_err},
                            ensure_ascii=False,
                        ).encode("utf-8"),
                        flags=FLAG_NONE,
                    )
                    self._dispatch_received_packet(err_packet)
                    continue

                if packet is not None:
                    self._dispatch_received_packet(packet)

            except ConnectionClosedError:
                if self.is_connected:
                    logger.warning("🔌 Server đã ngắt kết nối.")
                    disconnect_reason = "Server đã đóng kết nối."
                break
            except (ConnectionResetError, ConnectionAbortedError):
                if self.is_connected:
                    logger.warning("⚠️ Kết nối tới Server bị reset đột ngột.")
                    disconnect_reason = "Kết nối tới Server bị gián đoạn đột ngột."
                break
            except OSError:
                # Socket có thể đã được close bởi disconnect()
                break
            except Exception as exc:
                if self.is_connected:
                    logger.error("❌ Lỗi không mong muốn trong Receiver Loop: %s", exc)
                    disconnect_reason = f"Lỗi kết nối: {exc}"
                break

        was_connected = self.is_connected
        self.is_connected = False
        if was_connected and disconnect_reason and self.on_disconnected:
            try:
                self.on_disconnected(disconnect_reason)
            except Exception:
                pass

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
            # Mã hóa toàn bộ payload Chat Data Plane khi phù hợp:
            # - CHAT_BROADCAST: luôn mã hóa toàn packet (Server relay nguyên dạng nếu không giữ khóa).
            # - CHAT_DIRECT: mã hóa toàn packet nếu Server giữ khóa; ngược lại giữ metadata rõ
            #   và mã hóa riêng phần nội dung bên trong để Server định tuyến chính xác.
            encrypt_full_packet = False
            if self.crypto_key is not None and not (flags & FLAG_ENCRYPTED):
                mtype = int(msg_type)
                if mtype == int(MessageType.CHAT_BROADCAST):
                    encrypt_full_packet = True
                elif mtype == int(MessageType.CHAT_DIRECT):
                    encrypt_full_packet = self.server_encryption_enabled

            packet_bytes = create_packet(
                msg_type,
                payload,
                flags=flags,
                encrypt_key=self.crypto_key if encrypt_full_packet else None,
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
    def _update_peer_directory(self, peers: Any) -> None:
        """Cập nhật danh bạ địa chỉ IP:P2P_Port cục bộ từ dữ liệu Tracker."""
        if not isinstance(peers, dict):
            return
        with self._peer_dir_lock:
            for uname, info in peers.items():
                if isinstance(info, dict) and info.get("ip") and info.get("p2p_port"):
                    self.peer_directory[uname] = {
                        "username": info.get("username", uname),
                        "ip": str(info["ip"]),
                        "p2p_port": int(info["p2p_port"]),
                    }

    def _remove_peer_from_directory(self, username: str) -> None:
        """Xóa một peer khỏi danh bạ P2P cục bộ theo tên (không phân biệt hoa thường)."""
        target_key = username.lower()
        with self._peer_dir_lock:
            stale = [k for k in self.peer_directory if k.lower() == target_key]
            for k in stale:
                del self.peer_directory[k]

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
        self._update_peer_directory(data.get("peers"))
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
        """Xử lý danh sách user và thông tin P2P endpoint từ Tracker trả về."""
        try:
            data = packet.to_json()
            users = data.get("users", [])
            self._update_peer_directory(data.get("peers"))
        except Exception:
            users = []
        self.online_users = users
        self._user_list_result = users
        self._user_list_event.set()

    def _handle_user_status_broadcast(self, packet: Packet) -> None:
        """Cập nhật danh sách online & danh bạ P2P khi có người dùng JOINED / LEFT."""
        try:
            data = packet.to_json()
            event = data.get("event")
            user = data.get("username")
            if event == "JOINED" and user:
                if user not in self.online_users:
                    self.online_users.append(user)
                peer_info = data.get("peer")
                if isinstance(peer_info, dict) and peer_info.get("ip") and peer_info.get("p2p_port"):
                    self._update_peer_directory({user: peer_info})
                logger.info("👤 [%s] vừa tham gia hệ thống.", user)
            elif event == "LEFT" and user:
                if user in self.online_users:
                    self.online_users.remove(user)
                self._remove_peer_from_directory(user)
                logger.info("👤 [%s] vừa rời hệ thống.", user)
        except Exception as e:
            logger.error("Lỗi khi xử lý USER_STATUS_BROADCAST: %s", e)

    def _handle_peer_lookup_resp(self, packet: Packet) -> None:
        """Nhận kết quả tra cứu địa chỉ IP:P2P_Port (PEER_LOOKUP_RESP) từ Tracker Server."""
        try:
            data = packet.to_json()
        except Exception:
            return
        target = data.get("target") or data.get("username")
        resolved_name = data.get("username") or target
        if not target:
            return
        key = str(target).lower()
        if data.get("found") and data.get("ip") and data.get("p2p_port") and resolved_name:
            self._update_peer_directory({str(resolved_name): data})
        elif resolved_name:
            self._remove_peer_from_directory(str(resolved_name))

        with self._lookup_lock:
            ev = self._lookup_events.get(key)
            if ev is not None:
                self._lookup_results[key] = data
                ev.set()

    # ==========================================================================
    # QUẢN LÝ LISTENER & NHẬN FILE TRỰC TIẾP P2P (PEER-TO-PEER SERVER)
    # ==========================================================================
    def start_p2p_listener(self, bind_host: str = "0.0.0.0", port: Optional[int] = None) -> int:
        """Khởi động TCP Listener nhận kết nối P2P truyền file trực tiếp từ các Peer."""
        if self._p2p_running and self._p2p_server_sock is not None and self.p2p_port:
            return self.p2p_port

        target_port = self._configured_p2p_port if port is None else int(port)
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv_sock.bind((bind_host, target_port))
            srv_sock.listen(16)
            srv_sock.settimeout(0.5)
        except OSError:
            srv_sock.close()
            raise

        self._p2p_server_sock = srv_sock
        self.p2p_port = int(srv_sock.getsockname()[1])
        self._p2p_running = True
        self._p2p_accept_thread = threading.Thread(
            target=self._p2p_accept_loop,
            name=f"P2PListener-{self.client_name}-{self.p2p_port}",
            daemon=True,
        )
        self._p2p_accept_thread.start()
        logger.info("📡 Đã mở cổng P2P TCP Listener tại %s:%d", bind_host, self.p2p_port)
        return self.p2p_port

    def stop_p2p_listener(self) -> None:
        """Đóng P2P TCP Listener và thu dọn các luồng worker P2P đang chạy."""
        self._p2p_running = False
        srv_sock = self._p2p_server_sock
        self._p2p_server_sock = None
        if srv_sock:
            try:
                srv_sock.close()
            except OSError:
                pass

        if self._p2p_accept_thread and threading.current_thread() != self._p2p_accept_thread:
            self._p2p_accept_thread.join(timeout=1.0)
        self._p2p_accept_thread = None

        with self._p2p_workers_lock:
            workers = list(self._p2p_worker_threads)
            self._p2p_worker_threads.clear()
        for worker in workers:
            if threading.current_thread() != worker and worker.is_alive():
                worker.join(timeout=1.0)

        with self._incoming_files_lock:
            self.incoming_files.clear()
        self.p2p_port = None

    def _p2p_accept_loop(self) -> None:
        """Vòng lặp chấp nhận kết nối TCP trực tiếp từ các Peer gửi file."""
        while self._p2p_running and self._p2p_server_sock:
            try:
                peer_sock, peer_addr = self._p2p_server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            worker = threading.Thread(
                target=self._handle_p2p_connection,
                args=(peer_sock, peer_addr),
                name=f"P2PWorker-{peer_addr[0]}:{peer_addr[1]}",
                daemon=True,
            )
            with self._p2p_workers_lock:
                self._p2p_worker_threads = [t for t in self._p2p_worker_threads if t.is_alive()]
                self._p2p_worker_threads.append(worker)
            worker.start()

    def _notify_file_error(self, sender: str, file_name: str, reason: str) -> None:
        """Kích hoạt callback báo lỗi nhận/giải mã file một cách an toàn."""
        if self.on_file_error:
            try:
                self.on_file_error(sender, file_name, reason)
            except Exception:
                pass

    def _p2p_handshake_server(self, peer_sock: socket.socket) -> Optional[str]:
        """Xác thực bước bắt tay ngắn PEER_HELLO / PEER_HELLO_ACK trên socket P2P."""
        hello_pkt = recv_packet(peer_sock)
        if hello_pkt.msg_type != MessageType.PEER_HELLO:
            return None

        hello_data = hello_pkt.to_json()
        peer_sender = str(hello_data.get("sender") or "").strip()
        peer_ver = hello_data.get("protocol_version")
        if peer_ver != PROTOCOL_VERSION or not peer_sender:
            reject_ack = create_packet(
                MessageType.PEER_HELLO_ACK,
                {
                    "status": "REJECTED",
                    "protocol_version": PROTOCOL_VERSION,
                    "reason": "Phiên bản giao thức hoặc danh tính P2P không hợp lệ.",
                },
            )
            peer_sock.sendall(reject_ack)
            return None

        ok_ack = create_packet(
            MessageType.PEER_HELLO_ACK,
            {
                "status": "OK",
                "username": self.username or self.client_name,
                "protocol_version": PROTOCOL_VERSION,
            },
        )
        peer_sock.sendall(ok_ack)
        return peer_sender

    def _prepare_incoming_p2p_transfer(
        self,
        peer_sock: socket.socket,
        offer: Dict[str, Any],
        peer_sender: str,
    ) -> Optional[Tuple[IncomingFileTransfer, bool]]:
        """Kiểm tra FILE_OFFER_REQ, trả FILE_OFFER_RESP và tạo phiên nhận file."""
        file_id = offer["file_id"]
        sender = str(offer.get("sender") or peer_sender)
        raw_name = offer["file_name"]
        safe_file_name = os.path.basename(raw_name) or f"file_{file_id}"
        file_size = int(offer["file_size"])
        total_chunks = int(offer["total_chunks"])
        expected_sha256 = offer["sha256"]
        offer_encrypted = bool(offer.get("encrypted", False))
        recipient_name = self.username or self.client_name

        logger.info(
            "📥 [P2P] Nhận đề xuất file '%s' (%s bytes, %d chunks, encrypted=%s) từ '%s'.",
            safe_file_name,
            file_size,
            total_chunks,
            offer_encrypted,
            sender,
        )

        if not self.auto_accept_files:
            reason = "Người nhận từ chối nhận file."
            peer_sock.sendall(
                create_packet(
                    MessageType.FILE_OFFER_RESP,
                    {"file_id": file_id, "sender": sender, "recipient": recipient_name, "status": "REJECTED", "reason": reason},
                )
            )
            return None

        if offer_encrypted and not self.crypto_key:
            err_reason = "Tập tin được mã hóa AES nhưng bạn chưa nhập mật khẩu phòng."
            self._notify_file_error(sender, safe_file_name, err_reason)
            peer_sock.sendall(
                create_packet(
                    MessageType.FILE_OFFER_RESP,
                    {"file_id": file_id, "sender": sender, "recipient": recipient_name, "status": "REJECTED", "reason": err_reason},
                )
            )
            return None

        os.makedirs(self.download_dir, exist_ok=True)
        save_path = os.path.join(self.download_dir, safe_file_name)
        transfer = IncomingFileTransfer(
            file_id=file_id,
            sender=sender,
            file_name=safe_file_name,
            file_size=file_size,
            total_chunks=total_chunks,
            expected_sha256=expected_sha256,
            save_path=save_path,
        )
        with self._incoming_files_lock:
            self.incoming_files[file_id] = transfer

        peer_sock.sendall(
            create_packet(
                MessageType.FILE_OFFER_RESP,
                {"file_id": file_id, "sender": sender, "recipient": recipient_name, "status": "ACCEPTED"},
            )
        )
        logger.info("✅ [P2P] Đã đồng ý nhận file '%s' trực tiếp từ '%s'.", safe_file_name, sender)
        return transfer, offer_encrypted

    def _decode_p2p_chunk(self, chunk_pkt: Packet, offer_encrypted: bool) -> Tuple[Dict[str, Any], bytes]:
        """Giải mã (nếu có FLAG_ENCRYPTED) và tách metadata + chunk bytes từ FILE_CHUNK."""
        if chunk_pkt.is_encrypted:
            if not self.crypto_key:
                raise ValueError("Tập tin được mã hóa AES nhưng bạn chưa nhập mật khẩu phòng.")
            try:
                chunk_pkt = chunk_pkt.get_decrypted_packet(self.crypto_key)
            except InvalidToken as exc:
                raise ValueError("Mật khẩu giải mã AES không khớp giữa người gửi và bạn.") from exc
        elif offer_encrypted:
            raise ValueError("Chunk P2P không mang cờ mã hóa như FILE_OFFER_REQ đã thỏa thuận.")

        return unpack_chunk_payload(chunk_pkt.payload)

    def _finalize_p2p_transfer(self, peer_sock: socket.socket, transfer: IncomingFileTransfer) -> None:
        """Lắp ráp file hoàn chỉnh, kiểm tra SHA-256 và gửi FILE_ACK trực tiếp qua socket P2P."""
        with self._incoming_files_lock:
            self.incoming_files.pop(transfer.file_id, None)

        ok, reason = transfer.assemble_and_verify()
        if ok and self.on_file_received:
            try:
                self.on_file_received(transfer.sender, transfer.file_name, transfer.save_path)
            except Exception as exc:
                logger.error("Lỗi callback on_file_received: %s", exc)
        elif not ok:
            self._notify_file_error(transfer.sender, transfer.file_name, reason)

        ack_payload = {
            "file_id": transfer.file_id,
            "sender": transfer.sender,
            "recipient": self.username or self.client_name,
            "status": "SUCCESS" if ok else "FAILED",
            "reason": reason,
            "file_name": transfer.file_name,
            "save_path": transfer.save_path,
        }
        peer_sock.sendall(create_packet(MessageType.FILE_ACK, ack_payload))

    def _send_p2p_failure_ack(self, peer_sock: socket.socket, transfer: IncomingFileTransfer, reason: str) -> None:
        """Gửi FILE_ACK trạng thái FAILED về peer gửi trước khi đóng kênh P2P."""
        ack_payload = {
            "file_id": transfer.file_id,
            "sender": transfer.sender,
            "recipient": self.username or self.client_name,
            "status": "FAILED",
            "reason": reason,
            "file_name": transfer.file_name,
        }
        try:
            peer_sock.sendall(create_packet(MessageType.FILE_ACK, ack_payload))
            peer_sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def _handle_p2p_connection(self, peer_sock: socket.socket, peer_addr: Tuple[str, int]) -> None:
        """Xử lý trọn vẹn một phiên nhận file trực tiếp qua kết nối TCP P2P."""
        transfer: Optional[IncomingFileTransfer] = None
        try:
            peer_sock.settimeout(30.0)
            peer_sender = self._p2p_handshake_server(peer_sock)
            if not peer_sender:
                return

            offer_pkt = recv_packet(peer_sock)
            if offer_pkt.msg_type != MessageType.FILE_OFFER_REQ:
                logger.warning("⚠️ [P2P] Nhận gói tin không hợp lệ %s từ %s", offer_pkt.msg_type, peer_addr)
                return

            prepared = self._prepare_incoming_p2p_transfer(peer_sock, offer_pkt.to_json(), peer_sender)
            if prepared is None:
                return
            transfer, offer_encrypted = prepared

            while True:
                chunk_pkt = recv_packet(peer_sock)
                if chunk_pkt.msg_type != MessageType.FILE_CHUNK:
                    raise ProtocolError(f"Gói tin không mong đợi trên luồng FILE_CHUNK: {chunk_pkt.msg_type}")

                meta, chunk_data = self._decode_p2p_chunk(chunk_pkt, offer_encrypted)
                if meta.get("file_id") != transfer.file_id:
                    raise ProtocolError("Gói FILE_CHUNK sai file_id trên kết nối P2P.")

                is_finished = transfer.add_chunk(int(meta["chunk_index"]), chunk_data)
                if self.on_file_progress:
                    try:
                        self.on_file_progress(
                            transfer.file_id,
                            len(transfer.received_chunks),
                            transfer.total_chunks,
                            transfer.progress_percentage,
                        )
                    except Exception:
                        pass

                if is_finished:
                    self._finalize_p2p_transfer(peer_sock, transfer)
                    break

        except ValueError as err:
            err_reason = str(err)
            if transfer:
                with self._incoming_files_lock:
                    self.incoming_files.pop(transfer.file_id, None)
                logger.warning("🔒 [P2P] Lỗi giải mã/dữ liệu file '%s': %s", transfer.file_name, err_reason)
                self._notify_file_error(transfer.sender, transfer.file_name, err_reason)
                self._send_p2p_failure_ack(peer_sock, transfer, err_reason)
        except (ConnectionClosedError, ProtocolError, OSError) as exc:
            if transfer:
                with self._incoming_files_lock:
                    self.incoming_files.pop(transfer.file_id, None)
                err_reason = f"Kết nối P2P bị gián đoạn khi nhận file '{transfer.file_name}': {exc}"
                logger.warning("⚠️ [P2P] %s", err_reason)
                self._notify_file_error(transfer.sender, transfer.file_name, err_reason)
                self._send_p2p_failure_ack(peer_sock, transfer, err_reason)
        except Exception as exc:
            logger.error("❌ [P2P] Lỗi xử lý kết nối từ %s: %s", peer_addr, exc)
            if transfer:
                with self._incoming_files_lock:
                    self.incoming_files.pop(transfer.file_id, None)
        finally:
            try:
                peer_sock.close()
            except OSError:
                pass

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

        auth_payload: Dict[str, Any] = {"username": username}
        if self.p2p_port is not None:
            auth_payload["p2p_port"] = self.p2p_port
        if self.p2p_host:
            auth_payload["p2p_host"] = self.p2p_host

        success = self.send_packet(MessageType.AUTH_REQ, auth_payload)
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
        ts = time.time()

        # Nếu Client bật mã hóa mà Server không giữ khóa (E2EE relay),
        # giữ trường recipient rõ để Server định tuyến, nhưng mã hóa AES toàn bộ nội dung bên trong.
        if self.crypto_key is not None and not self.server_encryption_enabled:
            inner_data = json.dumps(
                {
                    "sender": sender_name,
                    "recipient": recipient,
                    "content": content,
                    "timestamp": ts,
                },
                ensure_ascii=False,
            )
            cipher_token = encrypt_payload(inner_data, self.crypto_key).decode("ascii")
            return self.send_packet(
                MessageType.CHAT_DIRECT,
                {
                    "sender": sender_name,
                    "recipient": recipient,
                    "e2ee": True,
                    "ciphertext": cipher_token,
                    "timestamp": ts,
                },
            )

        return self.send_packet(
            MessageType.CHAT_DIRECT,
            {
                "sender": sender_name,
                "recipient": recipient,
                "content": content,
                "timestamp": ts,
            },
        )

    def lookup_peer(
        self, target_username: str, timeout: float = 5.0
    ) -> Tuple[bool, Optional[Tuple[str, int]], str]:
        """
        Truy vấn Tracker Server (PEER_LOOKUP_REQ -> PEER_LOOKUP_RESP) để lấy (IP, P2P_Port) của peer.

        Returns:
            Tuple[bool, Optional[Tuple[str, int]], str]: (found, (ip, p2p_port) | None, message/reason).
        """
        if not self.is_connected:
            return False, None, "Chưa kết nối tới Server."

        target = str(target_username).strip()
        if not target:
            return False, None, "Tên người nhận không hợp lệ."

        key = target.lower()
        event = threading.Event()
        with self._lookup_lock:
            self._lookup_events[key] = event
            self._lookup_results.pop(key, None)

        if not self.send_packet(MessageType.PEER_LOOKUP_REQ, {"username": target}):
            with self._lookup_lock:
                self._lookup_events.pop(key, None)
            return False, None, "Không thể gửi yêu cầu tra cứu Peer lên Tracker Server."

        if not event.wait(timeout=timeout):
            with self._lookup_lock:
                self._lookup_events.pop(key, None)
                self._lookup_results.pop(key, None)
            return False, None, f"Quá thời gian tra cứu địa chỉ P2P cho '{target}' từ Tracker Server."

        with self._lookup_lock:
            self._lookup_events.pop(key, None)
            result = self._lookup_results.pop(key, {})

        if result.get("found") and result.get("ip") and result.get("p2p_port"):
            return True, (str(result["ip"]), int(result["p2p_port"])), "OK"

        reason = result.get("reason") or f"Không tìm thấy thông tin kết nối P2P cho '{target}'."
        return False, None, reason

    def _connect_p2p_peer(
        self,
        recipient: str,
        peer_ip: str,
        peer_port: int,
        timeout: float,
    ) -> Tuple[Optional[socket.socket], Optional[str]]:
        """Thiết lập kết nối TCP P2P trực tiếp tới peer và bắt tay PEER_HELLO / PEER_HELLO_ACK."""
        p2p_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect_timeout = min(timeout, 5.0)
        p2p_sock.settimeout(connect_timeout)
        try:
            p2p_sock.connect((peer_ip, peer_port))
            p2p_sock.settimeout(timeout)

            hello = create_packet(
                MessageType.PEER_HELLO,
                {
                    "sender": self.username or self.client_name,
                    "protocol_version": PROTOCOL_VERSION,
                },
            )
            p2p_sock.sendall(hello)

            ack_pkt = recv_packet(p2p_sock)
            if ack_pkt.msg_type != MessageType.PEER_HELLO_ACK:
                raise ProtocolError(f"Gói phản hồi handshake P2P không hợp lệ: {ack_pkt.msg_type}")

            ack_data = ack_pkt.to_json()
            if ack_data.get("status") != "OK":
                reason = ack_data.get("reason", "Peer từ chối kết nối P2P.")
                p2p_sock.close()
                return None, f"Kết nối P2P tới '{recipient}' bị từ chối: {reason}"

            return p2p_sock, None
        except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError, ConnectionClosedError, ProtocolError) as exc:
            try:
                p2p_sock.close()
            except OSError:
                pass
            return (
                None,
                f"Không thể kết nối P2P trực tiếp tới '{recipient}' tại {peer_ip}:{peer_port} ({exc}). "
                "Hệ thống không chuyển tiếp file qua Server.",
            )

    @staticmethod
    def _try_read_p2p_failure_ack(p2p_sock: socket.socket) -> Optional[str]:
        """Thử đọc gói FILE_ACK báo lỗi từ peer nhận khi luồng ghi bị ngắt sớm."""
        try:
            p2p_sock.settimeout(0.5)
            ack_pkt = recv_packet(p2p_sock)
            if ack_pkt.msg_type == MessageType.FILE_ACK:
                ack_data = ack_pkt.to_json()
                return ack_data.get("reason")
        except (ConnectionClosedError, ProtocolError, socket.timeout, TimeoutError, OSError):
            return None
        return None

    def send_file(
        self,
        recipient: str,
        file_path: str,
        progress_callback: Optional[Callable[[int, int, float], None]] = None,
        timeout: float = 30.0,
    ) -> Tuple[bool, str]:
        """
        Gửi một file trực tiếp P2P cho người dùng khác (không qua Server relay):
          1. Tra cứu IP:P2P_Port từ Tracker Server (PEER_LOOKUP_REQ -> PEER_LOOKUP_RESP).
          2. Mở kết nối TCP trực tiếp tới Peer nhận và bắt tay PEER_HELLO / PEER_HELLO_ACK.
          3. Gửi FILE_OFFER_REQ -> nhận FILE_OFFER_RESP -> stream FILE_CHUNK -> nhận FILE_ACK.

        Returns:
            Tuple[bool, str]: (Thành công hay không, Thông báo kết quả / lỗi).
        """
        if not self.is_connected:
            return False, "Chưa kết nối tới Server."

        from pathlib import Path

        path = Path(file_path)
        if not path.is_file():
            return False, f"File không tồn tại: {file_path}"

        file_size = path.stat().st_size
        total_chunks = max(1, (file_size + DEFAULT_CHUNK_SIZE - 1) // DEFAULT_CHUNK_SIZE)
        sha256 = calculate_file_hash(path)
        file_id = str(uuid.uuid4())[:8]

        # 1. Tra cứu địa chỉ P2P (IP:P2P_Port) từ Tracker Server
        found, endpoint, lookup_reason = self.lookup_peer(recipient, timeout=min(timeout, 5.0))
        if not found or not endpoint:
            return False, lookup_reason

        peer_ip, peer_port = endpoint
        logger.info("📡 [P2P] Đã tra cứu '%s' tại %s:%d. Đang mở kết nối trực tiếp...", recipient, peer_ip, peer_port)

        # 2. Mở kết nối TCP trực tiếp tới Peer nhận (không fallback qua Server)
        p2p_sock, conn_err = self._connect_p2p_peer(recipient, peer_ip, peer_port, timeout=timeout)
        if not p2p_sock:
            return False, conn_err or "Không thể thiết lập kết nối P2P."

        use_encryption = self.crypto_key is not None
        try:
            # 3. Gửi FILE_OFFER_REQ trực tiếp tới Peer nhận
            offer_payload = {
                "file_id": file_id,
                "sender": self.username or self.client_name,
                "recipient": recipient,
                "file_name": path.name,
                "file_size": file_size,
                "total_chunks": total_chunks,
                "sha256": sha256,
                "encrypted": use_encryption,
            }
            logger.info(
                "📤 [P2P] Đề xuất gửi file '%s' (%s bytes, %d chunks, encrypted=%s) tới '%s'...",
                path.name,
                file_size,
                total_chunks,
                use_encryption,
                recipient,
            )
            p2p_sock.sendall(create_packet(MessageType.FILE_OFFER_REQ, offer_payload))

            offer_resp_pkt = recv_packet(p2p_sock)
            if offer_resp_pkt.msg_type != MessageType.FILE_OFFER_RESP:
                return False, f"Phản hồi P2P không mong đợi khi đề nghị gửi file: {offer_resp_pkt.msg_type}"

            offer_resp = offer_resp_pkt.to_json()
            if offer_resp.get("status") != "ACCEPTED":
                return False, offer_resp.get("reason", "Người nhận từ chối nhận file.")

            logger.info("✅ [P2P] '%s' đã đồng ý! Bắt đầu truyền %d chunks trực tiếp...", recipient, total_chunks)

            # 4. Truyền từng chunk trực tiếp qua kênh TCP P2P (mã hóa toàn packet nếu bật AES)
            sent_chunks = 0
            chunk_iter = read_file_chunks(path, chunk_size=DEFAULT_CHUNK_SIZE) if file_size > 0 else [(0, b"")]
            for chunk_index, chunk_data in chunk_iter:
                chunk_payload = pack_chunk_payload(
                    file_id=file_id,
                    chunk_index=chunk_index,
                    total_chunks=total_chunks,
                    chunk_data=chunk_data,
                    encrypted=use_encryption,
                )
                pkt_bytes = create_packet(
                    MessageType.FILE_CHUNK,
                    chunk_payload,
                    encrypt_key=self.crypto_key if use_encryption else None,
                )
                try:
                    p2p_sock.sendall(pkt_bytes)
                except OSError as send_exc:
                    ack_reason = self._try_read_p2p_failure_ack(p2p_sock)
                    if ack_reason:
                        return False, f"Xác thực/giải mã file thất bại tại người nhận: {ack_reason}"
                    return False, f"Kết nối P2P bị gián đoạn khi đang truyền file tới '{recipient}': {send_exc}"

                sent_chunks += 1
                percent = (sent_chunks / total_chunks) * 100.0
                if progress_callback:
                    try:
                        progress_callback(sent_chunks, total_chunks, percent)
                    except Exception:
                        pass

            logger.info("⏳ [P2P] Đã truyền xong %d/%d chunks. Đang chờ FILE_ACK...", sent_chunks, total_chunks)

            # 5. Chờ FILE_ACK trực tiếp từ Peer nhận
            ack_pkt = recv_packet(p2p_sock)
            if ack_pkt.msg_type != MessageType.FILE_ACK:
                return False, f"Nhận gói tin không mong đợi thay cho FILE_ACK: {ack_pkt.msg_type}"

            ack_resp = ack_pkt.to_json()
            if ack_resp.get("status") == "SUCCESS":
                return True, f"File '{path.name}' đã gửi P2P thành công và xác thực toàn vẹn 100% (SHA-256 khớp)."
            return False, f"Xác thực file thất bại tại người nhận: {ack_resp.get('reason')}"

        except (socket.timeout, TimeoutError):
            return False, f"Quá thời gian chờ phản hồi P2P khi truyền file cho '{recipient}'."
        except (ConnectionClosedError, ProtocolError, OSError) as exc:
            return False, f"Lỗi truyền file P2P tới '{recipient}': {exc}"
        finally:
            try:
                p2p_sock.close()
            except OSError:
                pass

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
        if not self.is_connected and not self.sock and not self._p2p_server_sock:
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

        with self._peer_dir_lock:
            self.peer_directory.clear()
        with self._lookup_lock:
            for ev in self._lookup_events.values():
                ev.set()
            self._lookup_events.clear()
            self._lookup_results.clear()

        # Dừng luồng Heartbeat nếu đang chạy
        if self.heartbeat_sender:
            self.heartbeat_sender.stop()
            self.heartbeat_sender = None

        # Đóng P2P TCP Listener trước/song song với dọn socket Server
        self.stop_p2p_listener()

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
