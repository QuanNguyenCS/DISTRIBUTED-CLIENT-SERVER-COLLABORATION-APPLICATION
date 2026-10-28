"""
Module: client.client_core
Mô tả: Lớp Client chính quản lý TCP Socket, thực hiện kết nối tới Server,
thực hiện cơ chế bắt tay tầng ứng dụng (Application Handshake) và duy trì kết nối.
"""

from __future__ import annotations

import socket
from typing import Any, Dict, Optional

from common.logger import get_logger
from common.message_types import MessageType
from common.protocol import (
    PROTOCOL_VERSION,
    ConnectionClosedError,
    ProtocolError,
    create_packet,
    recv_packet,
)

logger = get_logger("client.core")


class ClientCore:
    """
    Lớp quản lý Client TCP ở tầng mạng.
    
    Vòng đời của Client Socket:
      1. Khởi tạo socket TCP: socket(AF_INET, SOCK_STREAM)
      2. Kết nối tới Server (IP, Port) bằng connect()
      3. Gửi gói tin HELLO_HANDSHAKE kèm thông tin phiên bản giao thức
      4. Chờ nhận phản hồi HANDSHAKE_ACK hoặc HANDSHAKE_REJECT từ Server
      5. Giao tiếp dữ liệu hoặc chủ động ngắt kết nối (DISCONNECT_NOTICE)
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

    def connect(self, timeout: float = 5.0, protocol_version: int = PROTOCOL_VERSION) -> bool:
        """
        Kết nối tới Server TCP và thực hiện bắt tay ứng dụng.

        Args:
            timeout: Thời gian tối đa chờ kết nối (giây).
            protocol_version: Phiên bản giao thức gửi đi (mặc định là PROTOCOL_VERSION).

        Returns:
            bool: True nếu kết nối và bắt tay thành công, False nếu thất bại.

        Raises:
            ConnectionRefusedError: Nếu Server từ chối kết nối (chưa chạy hoặc chặn port).
            TimeoutError / socket.timeout: Nếu hết thời gian chờ kết nối.
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

            # 2. Thực hiện 3-way handshake TCP ở tầng truyền vận
            self.sock.connect((self.server_host, self.server_port))
            logger.info("🔗 Đã thiết lập kết nối TCP thành công với %s:%d.", self.server_host, self.server_port)

            # 3. Thực hiện bắt tay tầng ứng dụng (Application Layer Handshake)
            handshake_success = self._perform_handshake(protocol_version=protocol_version)
            if handshake_success:
                self.is_connected = True
                # Bỏ timeout kết nối, đưa socket về chế độ bình thường
                self.sock.settimeout(None)
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
        """
        Gửi yêu cầu HELLO_HANDSHAKE và xử lý phản hồi từ Server.

        Args:
            protocol_version: Phiên bản giao thức đóng gói trong gói tin.

        Returns:
            bool: True nếu nhận được HANDSHAKE_ACK, False nếu bị từ chối hoặc lỗi.
        """
        if not self.sock:
            return False

        try:
            logger.info(
                "Đang gửi HELLO_HANDSHAKE (Client: '%s', Protocol v%d)...",
                self.client_name,
                protocol_version,
            )

            # 1. Đóng gói và gửi HELLO_HANDSHAKE
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

            # 2. Đọc gói tin phản hồi từ Server
            response = recv_packet(self.sock)

            # 3. Phân loại phản hồi
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

    def disconnect(self, send_notice: bool = True) -> None:
        """
        Chủ động ngắt kết nối với Server (Graceful Disconnect).

        Args:
            send_notice: Gửi thông điệp DISCONNECT_NOTICE trước khi đóng socket nếu True.
        """
        if not self.is_connected and not self.sock:
            return

        logger.info("Đang ngắt kết nối tới Server...")
        if self.sock and self.is_connected and send_notice:
            try:
                # Gửi thông báo ngắt kết nối lịch sự tới server
                disconnect_packet = create_packet(
                    MessageType.DISCONNECT_NOTICE,
                    {"reason": "Client graceful shutdown"},
                )
                self.sock.sendall(disconnect_packet)
            except OSError:
                pass

        self._cleanup_socket()
        self.is_connected = False
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
