"""
Module: server.server_core
Mô tả: Lớp Server chính quản lý TCP Socket Listener, chấp nhận kết nối từ các Client
và thực hiện cơ chế bắt tay tầng ứng dụng (Application Handshake Protocol).
"""

from __future__ import annotations

import socket
import sys
import threading
from typing import Optional, Tuple

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

logger = get_logger("server.core")


class ServerCore:
    """
    Lớp quản lý Server TCP ở tầng mạng.
    
    Vòng đời của Server Socket:
      1. Khởi tạo socket TCP: socket(AF_INET, SOCK_STREAM)
      2. Cấu hình cờ SO_REUSEADDR (tránh lỗi 'Address already in use' khi khởi động lại)
      3. Gán địa chỉ (bind) vào host và port quy định
      4. Lắng nghe (listen) với backlog xác định
      5. Chấp nhận kết nối (accept) và thực hiện bắt tay ứng dụng (Handshake)
    """

    DEFAULT_HOST: str = "0.0.0.0"
    DEFAULT_PORT: int = 9000
    DEFAULT_BACKLOG: int = 10

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        server_id: str = "CollabServer-01",
    ) -> None:
        self.host = host
        self.port = port
        self.server_id = server_id
        self.server_sock: Optional[socket.socket] = None
        self.is_running: bool = False
        self._lock = threading.Lock()

    def start(self) -> None:
        """
        Khởi động TCP Server socket, bind và listen.
        """
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
            self.is_running = True

            logger.info(
                "🚀 Server '%s' đã khởi động thành công và đang lắng nghe tại %s:%d (Backlog: %d)",
                self.server_id,
                self.host,
                self.port,
                self.DEFAULT_BACKLOG,
            )
        except OSError as exc:
            logger.critical("Không thể khởi động Server tại %s:%d: %s", self.host, self.port, exc)
            self.stop()
            raise

    def handle_handshake(
        self, client_sock: socket.socket, client_addr: Tuple[str, int]
    ) -> Tuple[bool, Optional[dict]]:
        """
        Thực hiện quy trình Bắt tay Ứng dụng (Application Handshake):
          1. Đọc gói tin HELLO_HANDSHAKE từ Client.
          2. Kiểm tra phiên bản giao thức (Protocol Version).
          3. Nếu hợp lệ: Gửi HANDSHAKE_ACK kèm metadata Server.
          4. Nếu không hợp lệ: Gửi HANDSHAKE_REJECT và thông báo lý do.

        Args:
            client_sock: Socket kết nối tới client.
            client_addr: Bộ (IP, Port) của client.

        Returns:
            Tuple[bool, Optional[dict]]: (Thành công hay không, Dữ liệu handshake nếu thành công).
        """
        try:
            # Đặt timeout ngắn cho quá trình handshake (tránh client treo socket vô tận)
            client_sock.settimeout(10.0)

            # Bước 1: Nhận gói tin đầu tiên từ client
            packet = recv_packet(client_sock)

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

            # Bước 2: Parse thông tin client gửi lên
            try:
                client_info = packet.to_json()
            except Exception as e:
                logger.warning("[%s:%d] Payload HELLO_HANDSHAKE không phải JSON: %s", client_addr[0], client_addr[1], e)
                client_info = {}

            client_version = client_info.get("client_version")
            client_name = client_info.get("client_name", "Unknown-Client")

            logger.info(
                "[%s:%d] Nhận yêu cầu bắt tay từ client '%s' (Protocol v%s)",
                client_addr[0],
                client_addr[1],
                client_name,
                client_version,
            )

            # Bước 3: Kiểm tra tính tương thích của phiên bản
            if client_version != PROTOCOL_VERSION:
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

            # Bước 4: Chấp nhận bắt tay và gửi HANDSHAKE_ACK
            ack_payload = {
                "status": "OK",
                "server_id": self.server_id,
                "version": PROTOCOL_VERSION,
                "message": f"Welcome to {self.server_id}! Handshake successful.",
            }
            client_sock.sendall(
                create_packet(MessageType.HANDSHAKE_ACK, ack_payload)
            )

            # Khôi phục blocking mode mặc định sau khi handshake xong
            client_sock.settimeout(None)

            logger.info(
                "✅ [%s:%d] Bắt tay thành công với client '%s'!",
                client_addr[0],
                client_addr[1],
                client_name,
            )
            return True, client_info

        except socket.timeout:
            logger.warning("[%s:%d] Quá thời gian chờ bắt tay (Handshake Timeout).", client_addr[0], client_addr[1])
            return False, None
        except (ConnectionClosedError, ProtocolError, OSError) as exc:
            logger.error("[%s:%d] Lỗi trong quá trình bắt tay: %s", client_addr[0], client_addr[1], exc)
            return False, None

    def accept_one(self) -> Tuple[Optional[socket.socket], Optional[Tuple[str, int]]]:
        """
        Chấp nhận một kết nối đến và thực hiện bắt tay ứng dụng.
        Dùng cho các bài test hoặc kịch bản đơn kết nối.

        Returns:
            Tuple[Optional[socket.socket], Optional[Tuple[str, int]]]:
                (client_socket, client_addr) nếu bắt tay thành công, ngược lại (None, None).
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

    def serve_forever(self) -> None:
        """
        Vòng lặp chính chấp nhận kết nối liên tục.
        (Nền tảng cho Giai đoạn 2 và sẵn sàng tích hợp Multi-threading ở Giai đoạn 3).
        """
        if not self.is_running:
            self.start()

        logger.info("Server đang chạy vòng lặp phục vụ kết nối (Nhấn Ctrl+C để dừng)...")
        try:
            while self.is_running:
                client_sock, client_addr = self.accept_one()
                if client_sock and client_addr:
                    # Ở Giai đoạn 2: In thông báo hoàn thành handshake
                    logger.info(
                        "🎉 Client [%s:%d] đã hoàn tất bắt tay TCP và Handshake ứng dụng.",
                        client_addr[0],
                        client_addr[1],
                    )
                    # Chờ client ngắt kết nối hoặc đóng socket
                    try:
                        # Kiểm tra xem client có gửi DISCONNECT_NOTICE không
                        packet = recv_packet(client_sock)
                        if packet.msg_type == MessageType.DISCONNECT_NOTICE:
                            logger.info("[%s:%d] Client chủ động ngắt kết nối.", client_addr[0], client_addr[1])
                    except (ConnectionClosedError, OSError):
                        logger.info("[%s:%d] Kết nối đã đóng.", client_addr[0], client_addr[1])
                    finally:
                        try:
                            client_sock.close()
                        except OSError:
                            pass
        except KeyboardInterrupt:
            logger.info("Nhận tín hiệu dừng từ bàn phím (Ctrl+C).")
        finally:
            self.stop()

    def stop(self) -> None:
        """
        Đóng socket server và dọn dẹp tài nguyên.
        """
        with self._lock:
            if not self.is_running and self.server_sock is None:
                return
            self.is_running = False
            if self.server_sock:
                try:
                    self.server_sock.close()
                    logger.info("🛑 Đã đóng Server socket thành công.")
                except OSError as exc:
                    logger.warning("Lỗi khi đóng server socket: %s", exc)
                finally:
                    self.server_sock = None
