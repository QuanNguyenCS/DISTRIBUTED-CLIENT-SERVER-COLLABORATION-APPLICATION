"""
File: client/gui/chat_view.py
Mô tả: Khung giao diện chính (Chat View) cho ứng dụng cộng tác phân tán.
Gồm:
  - Cột trái: Danh sách người dùng online, nút làm mới, thông tin tài khoản.
  - Khu vực trung tâm: Hệ thống Notebook Tabs (Phòng chung Global + các phòng Chat riêng 1-1).
  - Khung dưới: Ô nhập tin nhắn, nút Gửi, nút Chọn File đính kèm, nhãn trạng thái bảo mật.
"""

import time
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from typing import Callable, Dict, List, Optional, Tuple


def format_time(ts: Optional[float] = None) -> str:
    """Định dạng dấu thời gian thành HH:MM:SS."""
    if ts is None:
        ts = time.time()
    return time.strftime("%H:%M:%S", time.localtime(ts))


class ChatView(ttk.Frame):
    """
    Giao diện phòng chat hoàn chỉnh với kiến trúc phân tách tab (Tabbed Chat Interface).
    """

    def __init__(
        self,
        parent: tk.Widget,
        current_username: str,
        on_send_broadcast: Callable[[str], None],
        on_send_direct: Callable[[str, str], None],
        on_send_file: Callable[[str, str], None],
        on_refresh_users: Callable[[], None],
        on_logout: Callable[[], None],
        is_encrypted: bool = False,
    ) -> None:
        super().__init__(parent)
        self.parent = parent
        self.current_username = current_username
        self.on_send_broadcast = on_send_broadcast
        self.on_send_direct = on_send_direct
        self.on_send_file = on_send_file
        self.on_refresh_users = on_refresh_users
        self.on_logout = on_logout
        self.is_encrypted = is_encrypted

        # Quản lý các tab chat: tab_id -> ScrolledText widget
        self.chat_tabs: Dict[str, scrolledtext.ScrolledText] = {}
        # Danh sách người dùng online hiện tại
        self.online_users_list: List[str] = []

        self._build_ui()

    def _build_ui(self) -> None:
        # Layout chính dạng 2 cột: Cột trái (Users) | Cột phải (Chat & Input)
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # ----------------------------------------------------------------------
        # CỘT TRÁI: DANH SÁCH NGƯỜI DÙNG ONLINE
        # ----------------------------------------------------------------------
        left_frame = ttk.Frame(paned, padding=8, width=220)
        paned.add(left_frame, weight=1)

        # Thông tin tài khoản hiện tại
        my_card = ttk.LabelFrame(left_frame, text="Tài khoản của bạn", padding=6)
        my_card.pack(fill=tk.X, pady=(0, 8))

        user_badge = ttk.Label(
            my_card,
            text=f"👤 {self.current_username}",
            font=("Segoe UI", 10, "bold"),
            foreground="#1976D2",
        )
        user_badge.pack(anchor=tk.W)

        enc_text = "🔒 Bảo mật AES-256" if self.is_encrypted else "🔓 Không mã hóa"
        enc_color = "#2E7D32" if self.is_encrypted else "#757575"
        self.enc_lbl = ttk.Label(
            my_card,
            text=enc_text,
            font=("Segoe UI", 8, "italic"),
            foreground=enc_color,
        )
        self.enc_lbl.pack(anchor=tk.W)

        # Danh sách online
        self.users_title_lbl = ttk.Label(
            left_frame,
            text="👥 Người dùng Online (0)",
            font=("Segoe UI", 9, "bold"),
        )
        self.users_title_lbl.pack(anchor=tk.W, pady=(5, 3))

        # Listbox và Scrollbar
        list_container = ttk.Frame(left_frame)
        list_container.pack(fill=tk.BOTH, expand=True)

        self.users_listbox = tk.Listbox(
            list_container,
            font=("Segoe UI", 9),
            selectbackground="#BBDEFB",
            selectforeground="#0D47A1",
            activestyle="none",
            borderwidth=1,
            relief="solid",
        )
        list_scrollbar = ttk.Scrollbar(
            list_container, orient=tk.VERTICAL, command=self.users_listbox.yview
        )
        self.users_listbox.config(yscrollcommand=list_scrollbar.set)

        self.users_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bắt sự kiện Double-click để mở tab chat riêng
        self.users_listbox.bind("<Double-Button-1>", self._on_user_double_click)

        # Khung nút thao tác người dùng
        left_btn_frame = ttk.Frame(left_frame)
        left_btn_frame.pack(fill=tk.X, pady=(6, 0))

        refresh_btn = ttk.Button(
            left_btn_frame,
            text="🔄 Làm mới",
            command=self.on_refresh_users,
        )
        refresh_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))

        direct_btn = ttk.Button(
            left_btn_frame,
            text="💬 Nhắn riêng",
            command=self._open_selected_user_chat,
        )
        direct_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(3, 0))

        # Nút đăng xuất
        logout_btn = ttk.Button(
            left_frame,
            text="🔌 Đăng xuất",
            command=self.on_logout,
        )
        logout_btn.pack(fill=tk.X, pady=(6, 0))

        # ----------------------------------------------------------------------
        # CỘT PHẢI: KHUNG NOTEBOOK TABS VÀ Ô NHẬP LIỆU
        # ----------------------------------------------------------------------
        right_frame = ttk.Frame(paned, padding=8)
        paned.add(right_frame, weight=4)

        # Notebook chứa các tab trò chuyện
        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab mặc định: "💬 Phòng chung (Global)"
        self._create_chat_tab("global", "💬 Toàn thể (Global)")

        # Khung nhập liệu ở dưới cùng
        input_frame = ttk.Frame(right_frame, padding=(0, 6, 0, 0))
        input_frame.pack(fill=tk.X)

        self.entry_var = tk.StringVar()
        self.msg_entry = ttk.Entry(
            input_frame,
            textvariable=self.entry_var,
            font=("Segoe UI", 10),
        )
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6), ipady=3)
        self.msg_entry.bind("<Return>", lambda e: self._on_send_click())
        self.msg_entry.focus_set()

        # Nút Gửi File đính kèm 📎
        file_btn = ttk.Button(
            input_frame,
            text="📎 Gửi File",
            command=self._on_attach_file_click,
        )
        file_btn.pack(side=tk.LEFT, padx=(0, 4))

        # Nút Gửi tin nhắn
        send_btn = ttk.Button(
            input_frame,
            text="Gửi 📤",
            command=self._on_send_click,
        )
        send_btn.pack(side=tk.RIGHT)

    def _create_chat_tab(self, tab_id: str, title: str) -> scrolledtext.ScrolledText:
        """Tạo một tab trò chuyện mới trong Notebook."""
        tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(tab_frame, text=title)

        text_widget = scrolledtext.ScrolledText(
            tab_frame,
            wrap=tk.WORD,
            font=("Segoe UI", 9),
            state=tk.DISABLED,
            borderwidth=1,
            relief="solid",
        )
        text_widget.pack(fill=tk.BOTH, expand=True)

        # Cấu hình các style tag
        text_widget.tag_config("timestamp", foreground="#888888", font=("Segoe UI", 8))
        text_widget.tag_config("self_sender", foreground="#1976D2", font=("Segoe UI", 9, "bold"))
        text_widget.tag_config("other_sender", foreground="#7B1FA2", font=("Segoe UI", 9, "bold"))
        text_widget.tag_config("system_sender", foreground="#E65100", font=("Segoe UI", 9, "bold"))
        text_widget.tag_config("content", foreground="#212121", font=("Segoe UI", 9))
        text_widget.tag_config("file_badge", foreground="#2E7D32", font=("Segoe UI", 9, "bold"))
        text_widget.tag_config("error_badge", foreground="#D32F2F", font=("Segoe UI", 9, "italic"))

        self.chat_tabs[tab_id] = text_widget
        return text_widget

    def get_or_create_direct_tab(self, username: str) -> scrolledtext.ScrolledText:
        """Lấy tab chat riêng với một user, nếu chưa có thì tạo mới."""
        tab_id = f"user_{username.lower()}"
        if tab_id not in self.chat_tabs:
            title = f"🔒 @{username}"
            text_widget = self._create_chat_tab(tab_id, title)
            self.append_message(
                tab_id=tab_id,
                sender="Hệ thống",
                content=f"Bắt đầu cuộc trò chuyện riêng tư 1-1 với @{username}.",
                is_system=True,
            )
            return text_widget
        return self.chat_tabs[tab_id]

    def _get_current_active_tab_id(self) -> str:
        """Xác định tab đang được chọn trên giao diện."""
        selected_index = self.notebook.index(self.notebook.select())
        if selected_index == 0:
            return "global"
        # Tìm tab_id tương ứng
        tab_widget_name = self.notebook.tabs()[selected_index]
        for tid, txt_widget in self.chat_tabs.items():
            if str(txt_widget.master) == tab_widget_name:
                return tid
        return "global"

    def _get_recipient_for_tab(self, tab_id: str) -> Optional[str]:
        """Nếu tab hiện tại là tab chat riêng, trả về tên người nhận."""
        if tab_id.startswith("user_"):
            return tab_id[5:]  # Cắt tiền tố 'user_'
        return None

    def append_message(
        self,
        tab_id: str,
        sender: str,
        content: str,
        timestamp: Optional[float] = None,
        is_self: bool = False,
        is_system: bool = False,
        is_file: bool = False,
        is_error: bool = False,
    ) -> None:
        """
        Ghi một tin nhắn vào khung chat của tab tương ứng.
        """
        if tab_id not in self.chat_tabs:
            # Tạo tab nếu chưa có
            if tab_id.startswith("user_"):
                self.get_or_create_direct_tab(tab_id[5:])
            else:
                self._create_chat_tab(tab_id, tab_id)

        text_widget = self.chat_tabs[tab_id]
        text_widget.config(state=tk.NORMAL)

        ts_str = f"[{format_time(timestamp)}] "
        text_widget.insert(tk.END, ts_str, "timestamp")

        if is_system:
            text_widget.insert(tk.END, f"📢 {sender}: ", "system_sender")
            text_widget.insert(tk.END, f"{content}\n", "content")
        elif is_error:
            text_widget.insert(tk.END, f"⚠️ {sender}: ", "error_badge")
            text_widget.insert(tk.END, f"{content}\n", "error_badge")
        elif is_file:
            sender_tag = "self_sender" if is_self else "other_sender"
            text_widget.insert(tk.END, f"{sender}: ", sender_tag)
            text_widget.insert(tk.END, f"📁 {content}\n", "file_badge")
        else:
            sender_tag = "self_sender" if is_self else "other_sender"
            prefix = "Bạn: " if is_self else f"{sender}: "
            text_widget.insert(tk.END, prefix, sender_tag)
            text_widget.insert(tk.END, f"{content}\n", "content")

        text_widget.see(tk.END)
        text_widget.config(state=tk.DISABLED)

    def update_online_users(self, users: List[str]) -> None:
        """Cập nhật danh sách hiển thị người dùng online."""
        self.online_users_list = users
        self.users_title_lbl.config(text=f"👥 Người dùng Online ({len(users)})")

        self.users_listbox.delete(0, tk.END)
        for user in sorted(users):
            if user.lower() == self.current_username.lower():
                self.users_listbox.insert(tk.END, f"🟢 {user} (Bạn)")
            else:
                self.users_listbox.insert(tk.END, f"🟢 {user}")

    def _open_selected_user_chat(self) -> None:
        selected_indices = self.users_listbox.curselection()
        if not selected_indices:
            messagebox.showinfo("Thông báo", "Vui lòng chọn một người dùng từ danh sách.")
            return

        selected_text = self.users_listbox.get(selected_indices[0])
        # Lấy tên sạch bỏ ký tự biểu tượng
        target_username = selected_text.replace("🟢", "").replace("(Bạn)", "").strip()

        if target_username.lower() == self.current_username.lower():
            messagebox.showwarning("Cảnh báo", "Bạn không thể tự gửi tin nhắn riêng cho chính mình.")
            return

        # Mở hoặc focus vào tab chat riêng
        self.get_or_create_direct_tab(target_username)
        # Chuyển Notebook sang tab này
        tab_id = f"user_{target_username.lower()}"
        target_widget = self.chat_tabs[tab_id]
        self.notebook.select(target_widget.master)
        self.msg_entry.focus_set()

    def _on_user_double_click(self, event: tk.Event) -> None:
        self._open_selected_user_chat()

    def _on_send_click(self) -> None:
        content = self.entry_var.get().strip()
        if not content:
            return

        self.entry_var.set("")
        active_tab_id = self._get_current_active_tab_id()
        recipient = self._get_recipient_for_tab(active_tab_id)

        if recipient:
            # Gửi tin nhắn riêng (Direct message)
            self.on_send_direct(recipient, content)
            self.append_message(
                tab_id=active_tab_id,
                sender=self.current_username,
                content=content,
                is_self=True,
            )
        else:
            # Gửi tin nhắn chung (Broadcast)
            self.on_send_broadcast(content)
            # Tin nhắn broadcast sẽ được server phản hồi lại hoặc hiển thị ngay
            self.append_message(
                tab_id="global",
                sender=self.current_username,
                content=content,
                is_self=True,
            )

    def _on_attach_file_click(self) -> None:
        """Xử lý sự kiện nhấn nút Gửi File đính kèm 📎."""
        file_path = filedialog.askopenfilename(
            title="Chọn tập tin để gửi",
            filetypes=[("Tất cả tập tin", "*.*")],
        )
        if not file_path:
            return

        active_tab_id = self._get_current_active_tab_id()
        recipient = self._get_recipient_for_tab(active_tab_id)

        if not recipient:
            # Nếu đang ở phòng chung, yêu cầu chọn người nhận từ danh sách
            selected_indices = self.users_listbox.curselection()
            if selected_indices:
                selected_text = self.users_listbox.get(selected_indices[0])
                recipient = selected_text.replace("🟢", "").replace("(Bạn)", "").strip()

            if not recipient or recipient.lower() == self.current_username.lower():
                messagebox.showinfo(
                    "Chọn người nhận file",
                    "Vui lòng chọn một người nhận cụ thể từ danh sách Online (hoặc chuyển sang tab Chat riêng) để gửi file.",
                )
                return

        # Gọi callback gửi file
        self.on_send_file(recipient, file_path)
