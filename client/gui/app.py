"""
File: client/gui/app.py
Mô tả: Ứng dụng GUI chính (Tkinter Root Window) điều phối toàn bộ vòng đời và sự kiện.
Áp dụng mẫu hình Hàng đợi luồng an toàn (Queue Pattern) kết hợp root.after(50, ...)
đảm bảo 100% không bị treo giao diện (Zero UI Freeze) trong quá trình truyền file hoặc socket I/O.
"""

import os
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, Optional, Tuple

from common.logger import get_logger
from common.message_types import MessageType
from common.protocol import Packet
from client.client_core import ClientCore
from client.gui.chat_view import ChatView
from client.gui.file_progress import FileProgressDialog
from client.gui.login_view import LoginView

logger = get_logger("gui.app")


class CollabChatApp(tk.Tk):
    """
    Cửa sổ chính của ứng dụng client giao diện Tkinter.
    """

    def __init__(self) -> None:
        super().__init__()
        self.title("Ứng dụng Trò chuyện & Cộng tác Phân tán")
        self.geometry("900x620")
        self.minsize(750, 520)

        # Cấu hình chủ đề và phong cách giao diện ttk
        self._setup_style()

        # Hàng đợi trung chuyển sự kiện đa luồng từ ClientCore sang Main Thread
        self.gui_queue: queue.Queue = queue.Queue()

        # Đối tượng mạng tầng dưới
        self.client: Optional[ClientCore] = None
        self.current_username: str = ""
        self.is_encrypted: bool = False

        # Các khung giao diện chính
        self.current_view: Optional[ttk.Frame] = None
        self.login_view: Optional[LoginView] = None
        self.chat_view: Optional[ChatView] = None

        # Quản lý các hộp thoại tiến trình file: file_id -> FileProgressDialog
        self.file_dialogs: Dict[str, FileProgressDialog] = {}

        # Hiển thị màn hình đăng nhập đầu tiên
        self._show_login_view()

        # Bắt đầu vòng lặp định kỳ đọc sự kiện từ hàng đợi (Queue Worker)
        self.after(50, self._process_gui_queue)

        # Bắt sự kiện người dùng bấm nút [X] đóng cửa sổ
        self.protocol("WM_DELETE_WINDOW", self._on_window_close)

    def _setup_style(self) -> None:
        """Thiết lập màu sắc và font chữ chuẩn cho ttk."""
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(".", font=("Segoe UI", 9))
        style.configure("TButton", padding=5, font=("Segoe UI", 9))
        style.configure("TLabel", font=("Segoe UI", 9))
        style.configure("TEntry", padding=4)
        style.configure("TNotebook.Tab", padding=[12, 5], font=("Segoe UI", 9, "bold"))

    def _show_login_view(self) -> None:
        """Hiển thị khung giao diện đăng nhập."""
        if self.current_view:
            self.current_view.destroy()

        self.login_view = LoginView(self, on_connect=self._handle_login_request)
        self.login_view.pack(fill=tk.BOTH, expand=True)
        self.current_view = self.login_view

    def _show_chat_view(self) -> None:
        """Chuyển sang khung giao diện phòng chat sau khi xác thực thành công."""
        if self.current_view:
            self.current_view.destroy()

        self.chat_view = ChatView(
            self,
            current_username=self.current_username,
            on_send_broadcast=self._on_send_broadcast,
            on_send_direct=self._on_send_direct,
            on_send_file=self._on_send_file,
            on_refresh_users=self._on_refresh_users,
            on_logout=self._on_logout,
            is_encrypted=self.is_encrypted,
        )
        self.chat_view.pack(fill=tk.BOTH, expand=True)
        self.current_view = self.chat_view

        # Cập nhật danh sách online ban đầu
        if self.client and self.client.online_users:
            self.chat_view.update_online_users(self.client.online_users)

    # ==========================================================================
    # XỬ LÝ ĐĂNG NHẬP TRÊN LUỒNG PHỤ (NON-BLOCKING LOGIN)
    # ==========================================================================
    def _handle_login_request(
        self,
        host: str,
        port: int,
        username: str,
        passphrase: Optional[str] = None,
    ) -> None:
        """Chạy việc kết nối và xác thực trên background thread để không đơ UI."""
        def worker():
            try:
                client = ClientCore(
                    server_host=host,
                    server_port=port,
                    client_name=username,
                )

                if passphrase:
                    client.enable_encryption(passphrase)
                    self.is_encrypted = True
                else:
                    self.is_encrypted = False

                # Đăng ký các callback để đẩy gói tin vào gui_queue
                self._bind_client_callbacks(client)

                # 1. Kết nối và bắt tay Handshake
                if not client.connect(timeout=4.0):
                    self.gui_queue.put(("login_failed", "Không thể bắt tay với Server. Vui lòng kiểm tra IP/Port."))
                    return

                # 2. Xác thực tài khoản
                ok, reason = client.authenticate(username, timeout=4.0)
                if not ok:
                    client.disconnect()
                    self.gui_queue.put(("login_failed", reason))
                    return

                # Đăng nhập thành công!
                self.client = client
                self.current_username = username
                self.gui_queue.put(("login_success", username))

            except ConnectionRefusedError:
                self.gui_queue.put(("login_failed", f"Không tìm thấy Server đang chạy tại {host}:{port}."))
            except Exception as exc:
                logger.error("Lỗi đăng nhập: %s", exc)
                self.gui_queue.put(("login_failed", f"Lỗi: {exc}"))

        threading.Thread(target=worker, daemon=True).start()

    def _bind_client_callbacks(self, client: ClientCore) -> None:
        """Đăng ký các hàm đón nhận gói tin từ socket receiver và chuyển vào GUI queue."""
        def _safe_json(pkt: Packet) -> dict:
            try:
                return pkt.to_json()
            except Exception:
                return {"message": pkt.to_text(), "content": pkt.to_text()}

        def on_broadcast(pkt: Packet):
            self.gui_queue.put(("chat_broadcast", _safe_json(pkt)))

        def on_direct(pkt: Packet):
            self.gui_queue.put(("chat_direct", _safe_json(pkt)))

        def on_user_status(pkt: Packet):
            self.gui_queue.put(("user_status", _safe_json(pkt)))

        def on_user_list(pkt: Packet):
            self.gui_queue.put(("user_list", _safe_json(pkt)))

        def on_error(pkt: Packet):
            self.gui_queue.put(("error_notice", _safe_json(pkt)))

        client.register_callback(MessageType.CHAT_BROADCAST, on_broadcast)
        client.register_callback(MessageType.CHAT_DIRECT, on_direct)
        client.register_callback(MessageType.USER_STATUS_BROADCAST, on_user_status)
        client.register_callback(MessageType.USER_LIST_RESP, on_user_list)
        client.register_callback(MessageType.ERROR_NOTICE, on_error)

        # Hook nhận file và thông báo lỗi / mất kết nối
        def on_file_received_done(sender: str, file_name: str, save_path: str):
            self.gui_queue.put(("incoming_file_done", (sender, file_name, save_path)))

        def on_file_error(sender: str, file_name: str, reason: str):
            self.gui_queue.put(("file_error", (sender, file_name, reason)))

        def on_disconnected(reason: str):
            self.gui_queue.put(("disconnected", reason))

        client.on_file_received = on_file_received_done
        client.on_file_error = on_file_error
        client.on_disconnected = on_disconnected

    # ==========================================================================
    # VÒNG LẶP ĐỌC HÀNG ĐỢI SỰ KIỆN (QUEUE CONSUMER ON MAIN THREAD)
    # ==========================================================================
    def _process_gui_queue(self) -> None:
        """
        Được gọi mỗi 50ms bởi Tkinter Main Thread.
        Lấy tất cả các sự kiện mạng đang chờ và cập nhật giao diện người dùng an toàn.
        """
        try:
            while True:
                event_type, data = self.gui_queue.get_nowait()
                self._dispatch_gui_event(event_type, data)
        except queue.Empty:
            pass
        finally:
            self.after(50, self._process_gui_queue)

    def _dispatch_gui_event(self, event_type: str, data: any) -> None:
        """Phân phối sự kiện GUI tới đúng View."""
        if event_type == "login_success":
            self._show_chat_view()
            if self.chat_view:
                p2p_note = f" (Cổng P2P: {self.client.p2p_port})" if self.client and self.client.p2p_port else ""
                self.chat_view.append_message(
                    tab_id="global",
                    sender="Hệ thống",
                    content=f"Chào mừng {data} đã tham gia phòng cộng tác!{p2p_note}",
                    is_system=True,
                )

        elif event_type == "login_failed":
            if self.login_view:
                self.login_view.set_error(str(data))

        elif event_type == "chat_broadcast":
            if self.chat_view:
                sender = data.get("sender", "Ẩn danh")
                # Không in lại tin nhắn do chính mình gửi (vì đã hiển thị tức thời)
                if sender.lower() != self.current_username.lower():
                    content = data.get("content") or data.get("text", "")
                    ts = data.get("timestamp")
                    self.chat_view.append_message(
                        tab_id="global",
                        sender=sender,
                        content=content,
                        timestamp=ts,
                    )

        elif event_type == "chat_direct":
            if self.chat_view:
                sender = data.get("sender", "Ẩn danh")
                content = data.get("content") or data.get("text", "")
                ts = data.get("timestamp")
                tab_id = f"user_{sender.lower()}"
                self.chat_view.get_or_create_direct_tab(sender)
                self.chat_view.append_message(
                    tab_id=tab_id,
                    sender=sender,
                    content=content,
                    timestamp=ts,
                )

        elif event_type == "user_status":
            event_name = data.get("event")
            username = data.get("username")
            online_users = data.get("online_users", [])

            if self.chat_view:
                if online_users:
                    self.chat_view.update_online_users(online_users)

                msg = (
                    f"Người dùng '{username}' vừa tham gia phòng."
                    if event_name == "JOINED"
                    else f"Người dùng '{username}' đã rời phòng."
                )
                self.chat_view.append_message(
                    tab_id="global",
                    sender="Hệ thống",
                    content=msg,
                    is_system=True,
                )

        elif event_type == "user_list":
            users = data.get("users", [])
            if self.chat_view:
                self.chat_view.update_online_users(users)

        elif event_type == "error_notice":
            msg = data.get("message", "Đã xảy ra lỗi.")
            if self.chat_view:
                self.chat_view.append_message(
                    tab_id="global",
                    sender="Cảnh báo",
                    content=msg,
                    is_error=True,
                )
            else:
                messagebox.showerror("Thông báo lỗi", msg)

        elif event_type == "file_progress_update":
            file_id, sent, total, pct = data
            dlg = self.file_dialogs.get(file_id)
            if dlg and dlg.winfo_exists():
                dlg.update_progress(sent, total, pct)

        elif event_type == "file_send_finished":
            file_id, success, message, target_user, file_name = data
            dlg = self.file_dialogs.pop(file_id, None)
            if dlg and dlg.winfo_exists():
                dlg.set_completed(success, message)
            if self.chat_view:
                tab_id = f"user_{target_user.lower()}"
                self.chat_view.get_or_create_direct_tab(target_user)
                if success:
                    self.chat_view.append_message(
                        tab_id=tab_id,
                        sender=self.current_username,
                        content=f"Đã gửi P2P file '{file_name}' thành công tới @{target_user}.",
                        is_file=True,
                        is_self=True,
                    )
                else:
                    self.chat_view.append_message(
                        tab_id=tab_id,
                        sender="Cảnh báo",
                        content=f"Gửi file P2P '{file_name}' tới @{target_user} thất bại: {message}",
                        is_error=True,
                    )

        elif event_type == "incoming_file_done":
            sender, file_name, save_path = data
            if self.chat_view:
                tab_id = f"user_{sender.lower()}"
                self.chat_view.get_or_create_direct_tab(sender)
                self.chat_view.append_message(
                    tab_id=tab_id,
                    sender=sender,
                    content=f"Đã nhận thành công file '{file_name}' (Lưu tại: {save_path})",
                    is_file=True,
                )
                self.chat_view.append_message(
                    tab_id="global",
                    sender="Hệ thống",
                    content=f"Đã nhận file '{file_name}' từ @{sender}.",
                    is_system=True,
                )

        elif event_type == "file_error":
            sender, file_name, reason = data
            err_msg = f"Nhận file '{file_name}' từ @{sender} thất bại: {reason}"
            if self.chat_view:
                tab_id = f"user_{sender.lower()}"
                self.chat_view.get_or_create_direct_tab(sender)
                self.chat_view.append_message(
                    tab_id=tab_id,
                    sender="Cảnh báo",
                    content=err_msg,
                    is_error=True,
                )
                self.chat_view.append_message(
                    tab_id="global",
                    sender="Cảnh báo",
                    content=err_msg,
                    is_error=True,
                )
            else:
                messagebox.showerror("Lỗi nhận file", err_msg)

        elif event_type == "disconnected":
            reason = data or "Kết nối tới Server đã bị ngắt."
            if self.chat_view:
                self.chat_view.append_message(
                    tab_id="global",
                    sender="Cảnh báo",
                    content=f"Mất kết nối tới Server: {reason}",
                    is_error=True,
                )

    # ==========================================================================
    # CÁC HÀNH ĐỘNG DO USER KÍCH HOẠT TỪ GIAO DIỆN
    # ==========================================================================
    def _on_send_broadcast(self, content: str) -> None:
        if self.client and self.client.is_connected:
            threading.Thread(
                target=self.client.send_broadcast,
                args=(content,),
                daemon=True,
            ).start()

    def _on_send_direct(self, recipient: str, content: str) -> None:
        if self.client and self.client.is_connected:
            threading.Thread(
                target=self.client.send_direct_message,
                args=(recipient, content),
                daemon=True,
            ).start()

    def _on_send_file(self, recipient: str, file_path: str) -> None:
        """Gửi file trong luồng nền tách biệt và hiển thị thanh tiến trình."""
        if not self.client or not self.client.is_connected:
            messagebox.showwarning("Cảnh báo", "Bạn chưa kết nối tới server.")
            return

        file_name = os.path.basename(file_path)
        try:
            file_size = os.path.getsize(file_path)
        except OSError as e:
            messagebox.showerror("Lỗi tập tin", f"Không thể đọc file: {e}")
            return

        chunk_size = 32 * 1024
        total_chunks = max(1, (file_size + chunk_size - 1) // chunk_size)
        file_id = f"{self.current_username}_{int(time.time() * 1000)}"

        # Mở hộp thoại popup tiến trình
        dlg = FileProgressDialog(
            parent=self,
            title=f"Gửi tập tin tới @{recipient}",
            file_name=file_name,
            file_size=file_size,
            total_chunks=total_chunks,
            direction="upload",
        )
        self.file_dialogs[file_id] = dlg

        def progress_cb(sent: int, total: int, pct: float):
            self.gui_queue.put(("file_progress_update", (file_id, sent, total, pct)))

        def worker():
            try:
                ok, msg = self.client.send_file(
                    recipient=recipient,
                    file_path=file_path,
                    progress_callback=progress_cb,
                    timeout=60.0,
                )
            except Exception as exc:
                ok, msg = False, f"Lỗi khi gửi file: {exc}"
            self.gui_queue.put(
                ("file_send_finished", (file_id, ok, msg, recipient, file_name))
            )

        threading.Thread(target=worker, daemon=True).start()

    def _on_refresh_users(self) -> None:
        if self.client and self.client.is_connected:
            threading.Thread(
                target=self.client.request_user_list,
                daemon=True,
            ).start()

    def _on_logout(self) -> None:
        if self.client:
            self.client.disconnect()
            self.client = None
        self._show_login_view()

    def _on_window_close(self) -> None:
        """Đóng ứng dụng an toàn khi người dùng bấm nút [X]."""
        if self.client and self.client.is_connected:
            try:
                self.client.disconnect()
            except Exception:
                pass
        self.destroy()
