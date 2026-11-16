"""
Module: server.session_manager
Mô tả: Quản lý phiên và trạng thái người dùng trực tuyến (Active User Sessions).
Đảm bảo an toàn đa luồng (Thread-Safety) với threading.Lock, chống xung đột
dữ liệu (Race Condition) khi nhiều Client đăng nhập hoặc đăng xuất đồng thời.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from common.logger import get_logger

if TYPE_CHECKING:
    from server.client_handler import ClientHandler

logger = get_logger("server.session")


@dataclass
class UserSession:
    """Đại diện cho một phiên làm việc của người dùng đã xác thực thành công."""

    username: str
    handler: Any  # ClientHandler
    address: Tuple[str, int]
    p2p_port: Optional[int] = None
    p2p_host: Optional[str] = None
    login_time: float = field(default_factory=time.time)
    identity_key: Optional[str] = None
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @property
    def effective_ip(self) -> str:
        """Địa chỉ IP có thể kết nối P2P (mặc định dùng IP thực tế Tracker nhìn thấy)."""
        if self.p2p_host and self.p2p_host not in ("0.0.0.0", ""):
            return self.p2p_host
        return self.address[0]

    def to_peer_dict(self) -> Dict[str, Any]:
        """Thông tin điểm cuối P2P phục vụ Tracker Lookup."""
        return {
            "username": self.username,
            "ip": self.effective_ip,
            "p2p_port": self.p2p_port,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Chuyển đổi thông tin session thành dict để serialize JSON."""
        return {
            "username": self.username,
            "ip": self.effective_ip,
            "port": self.address[1],
            "p2p_port": self.p2p_port,
            "login_time": self.login_time,
        }


class SessionManager:
    """
    Bộ quản lý phiên người dùng tập trung trên Server.

    Quy tắc an toàn:
      - Mọi thao tác đọc/ghi vào dictionary active_users đều phải được bao bọc bởi self._lock.
      - Tên người dùng không phân biệt hoa thường khi kiểm tra trùng lặp (vd: 'Alice' và 'alice' coi là một).
    """

    # Biểu thức chính quy cho username hợp lệ: 3 - 20 ký tự chữ cái, số, gạch dưới, gạch ngang
    USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{3,20}$")

    def __init__(self) -> None:
        # Bảng tra cứu chính: normalized_username (chữ thường) -> UserSession
        self._sessions: Dict[str, UserSession] = {}
        # Khóa Mutex đồng bộ luồng
        self._lock = threading.Lock()

    @classmethod
    def validate_username(cls, username: str) -> Tuple[bool, str]:
        """
        Kiểm tra tính hợp lệ của Username theo quy chuẩn.

        Args:
            username: Tên người dùng cần kiểm tra.

        Returns:
            Tuple[bool, str]: (Hợp lệ hay không, Thông báo lý do nếu không hợp lệ).
        """
        if not username or not isinstance(username, str):
            return False, "Username không được để trống."

        username = username.strip()
        if len(username) < 3:
            return False, "Username quá ngắn (tối thiểu 3 ký tự)."
        if len(username) > 20:
            return False, "Username quá dài (tối đa 20 ký tự)."

        if not cls.USERNAME_REGEX.match(username):
            return (
                False,
                "Username chỉ được chứa chữ cái, chữ số, gạch dưới (_) hoặc gạch ngang (-).",
            )

        return True, "Hợp lệ"

    def register_user(
        self,
        username: str,
        handler: Any,
        address: Tuple[str, int],
        p2p_port: Optional[int] = None,
        p2p_host: Optional[str] = None,
        identity_key: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[UserSession]]:
        """
        Đăng ký một người dùng mới vào danh bạ trực tuyến (Thread-Safe).

        Args:
            username: Tên người dùng muốn đăng ký.
            handler: Đối tượng ClientHandler đang xử lý kết nối này.
            address: Bộ (IP, Port) kết nối tới Server.
            p2p_port: Cổng TCP P2P Client đang lắng nghe để nhận file (nếu có).
            p2p_host: Địa chỉ IP P2P khai báo (nếu không truyền sẽ lấy IP thực tế từ address).

        Returns:
            Tuple[bool, str, Optional[UserSession]]:
                (Thành công hay không, Lý do, Đối tượng UserSession nếu thành công).
        """
        # 1. Kiểm tra định dạng username
        is_valid, reason = self.validate_username(username)
        if not is_valid:
            return False, reason, None

        clean_username = username.strip()
        key = clean_username.lower()

        valid_p2p_port: Optional[int] = None
        if (
            isinstance(p2p_port, int)
            and not isinstance(p2p_port, bool)
            and 1 <= p2p_port <= 65535
        ):
            valid_p2p_port = p2p_port

        clean_p2p_host: Optional[str] = None

        # 2. Kiểm tra trùng lặp và đăng ký trong khối khóa an toàn
        with self._lock:
            if key in self._sessions:
                logger.warning(
                    "Đăng ký thất bại: Username '%s' đã có người sử dụng.",
                    clean_username,
                )
                return (
                    False,
                    f"Username '{clean_username}' đã có người sử dụng. Vui lòng chọn tên khác.",
                    None,
                )

            session = UserSession(
                username=clean_username,
                handler=handler,
                address=address,
                p2p_port=valid_p2p_port,
                p2p_host=clean_p2p_host,
                identity_key=identity_key,
            )
            self._sessions[key] = session
            online_count = len(self._sessions)

        logger.info(
            "✅ [SessionManager] Đăng ký thành công User '%s' (%s:%d | P2P port: %s). Tổng online: %d",
            clean_username,
            address[0],
            address[1],
            valid_p2p_port or "N/A",
            online_count,
        )
        return True, "Đăng nhập thành công.", session

    def unregister_user(self, username: str) -> Optional[UserSession]:
        """
        Hủy đăng ký người dùng khi đăng xuất hoặc ngắt kết nối (Thread-Safe).

        Args:
            username: Tên người dùng cần hủy.

        Returns:
            Optional[UserSession]: Phiên đã bị xóa hoặc None nếu không tìm thấy.
        """
        if not username:
            return None

        key = username.strip().lower()
        with self._lock:
            session = self._sessions.pop(key, None)
            online_count = len(self._sessions)

        if session:
            logger.info(
                "❌ [SessionManager] Đã hủy phiên User '%s'. Tổng online còn lại: %d",
                session.username,
                online_count,
            )
        return session

    def unregister_by_handler(self, handler: Any) -> Optional[UserSession]:
        """
        Tìm và hủy đăng ký phiên dựa trên đối tượng ClientHandler (dùng khi socket bị đứt).
        """
        with self._lock:
            found_key: Optional[str] = None
            found_session: Optional[UserSession] = None
            for key, session in self._sessions.items():
                if session.handler is handler:
                    found_key = key
                    found_session = session
                    break

            if found_key:
                del self._sessions[found_key]
                logger.info(
                    "❌ [SessionManager] Hủy phiên User '%s' qua handler. Tổng online: %d",
                    found_session.username if found_session else "",
                    len(self._sessions),
                )
                return found_session
        return None

    def get_session(self, username: str) -> Optional[UserSession]:
        """Lấy phiên của một người dùng theo tên (Thread-Safe)."""
        key = username.strip().lower()
        with self._lock:
            return self._sessions.get(key)

    def is_online(self, username: str) -> bool:
        """Kiểm tra một người dùng có đang online hay không."""
        key = username.strip().lower()
        with self._lock:
            return key in self._sessions

    def get_all_users(self) -> List[str]:
        """
        Lấy danh sách tên hiển thị của tất cả người dùng đang online (Thread-Safe).
        """
        with self._lock:
            return [session.username for session in self._sessions.values()]

    def get_all_peer_endpoints(self) -> Dict[str, Dict[str, Any]]:
        """
        Lấy danh bạ IP:P2P_Port của các người dùng đang mở cổng P2P (Thread-Safe).
        """
        with self._lock:
            return {
                session.username: session.to_peer_dict()
                for session in self._sessions.values()
                if session.p2p_port is not None
            }

    def get_user_count(self) -> int:
        """Lấy tổng số lượng người dùng đang online."""
        with self._lock:
            return len(self._sessions)

    def clear(self) -> None:
        """Xóa toàn bộ phiên (khi Server tắt)."""
        with self._lock:
            self._sessions.clear()
