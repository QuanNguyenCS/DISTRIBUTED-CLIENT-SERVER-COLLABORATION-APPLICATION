"""
File: client/gui/login_view.py
Mô tả: Giao diện đăng nhập (Login View) cho ứng dụng phân tán.
Cho phép người dùng nhập IP Server, Port và Tên đăng nhập; mã hóa AES được bật tự động.
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable


class LoginView(ttk.Frame):
    """
    Khung giao diện đăng nhập và thiết lập thông số kết nối TCP.
    """

    def __init__(
        self,
        parent: tk.Widget,
        on_connect: Callable[[str, int, str], None],
    ) -> None:
        """
        Khởi tạo LoginView.

        Args:
            parent: Widget cha (thường là root Tk).
            on_connect: Callback nhận (host, port, username).
        """
        super().__init__(parent, padding=25)
        self.parent = parent
        self.on_connect_callback = on_connect

        self._build_ui()

    def _build_ui(self) -> None:
        # Tiêu đề chính
        title_lbl = ttk.Label(
            self,
            text="HỆ THỐNG TRÒ CHUYỆN & CỘNG TÁC",
            font=("Segoe UI", 16, "bold"),
            foreground="#1976D2",
        )
        title_lbl.pack(pady=(0, 5))

        subtitle_lbl = ttk.Label(
            self,
            text="Distributed Client-Server Socket Collaboration",
            font=("Segoe UI", 9, "italic"),
            foreground="#555555",
        )
        subtitle_lbl.pack(pady=(0, 20))

        # Khung chứa các ô nhập liệu
        form_frame = ttk.Frame(self)
        form_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Server Host
        ttk.Label(form_frame, text="Địa chỉ Server IP:", font=("Segoe UI", 9, "bold")).grid(
            row=0, column=0, sticky=tk.W, pady=6
        )
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.host_entry = ttk.Entry(form_frame, textvariable=self.host_var, width=32)
        self.host_entry.grid(row=0, column=1, sticky=tk.EW, pady=6, padx=(10, 0))

        # 2. Server Port
        ttk.Label(form_frame, text="Cổng kết nối (Port):", font=("Segoe UI", 9, "bold")).grid(
            row=1, column=0, sticky=tk.W, pady=6
        )
        self.port_var = tk.StringVar(value="9000")
        self.port_entry = ttk.Entry(form_frame, textvariable=self.port_var, width=32)
        self.port_entry.grid(row=1, column=1, sticky=tk.EW, pady=6, padx=(10, 0))

        # 3. Username
        ttk.Label(form_frame, text="Tên người dùng (Username):", font=("Segoe UI", 9, "bold")).grid(
            row=2, column=0, sticky=tk.W, pady=6
        )
        self.user_var = tk.StringVar(value="")
        self.user_entry = ttk.Entry(form_frame, textvariable=self.user_var, width=32)
        self.user_entry.grid(row=2, column=1, sticky=tk.EW, pady=6, padx=(10, 0))

        # 4. Thông báo chế độ bảo mật tự động (không cần nhập mật khẩu phòng)
        security_badge = ttk.Label(
            form_frame,
            text="🔒 Bảo mật tự động: AES (Fernet) + P2P X25519 đang bật",
            font=("Segoe UI", 8, "italic"),
            foreground="#2E7D32",
        )
        security_badge.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(8, 0))

        # Nhãn hiển thị trạng thái / báo lỗi
        self.status_lbl = ttk.Label(
            self,
            text="Sẵn sàng kết nối tới Server.",
            foreground="#666666",
            font=("Segoe UI", 9),
            wraplength=380,
            justify=tk.CENTER,
        )
        self.status_lbl.pack(pady=15)

        # Nút Đăng nhập & Tham gia
        self.connect_btn = ttk.Button(
            self,
            text="🚀 Kết nối & Tham gia phòng",
            command=self._on_submit,
        )
        self.connect_btn.pack(fill=tk.X, ipady=5)

        # Bắt sự kiện phím Enter
        self.user_entry.bind("<Return>", lambda e: self._on_submit())
        self.host_entry.bind("<Return>", lambda e: self._on_submit())
        self.port_entry.bind("<Return>", lambda e: self._on_submit())

        # Focus mặc định vào Username
        self.user_entry.focus_set()

    def _on_submit(self) -> None:
        host = self.host_var.get().strip()
        port_str = self.port_var.get().strip()
        username = self.user_var.get().strip()

        if not host:
            self.set_error("Vui lòng nhập địa chỉ IP của Server.")
            self.host_entry.focus_set()
            return

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            self.set_error("Cổng Port phải là một số nguyên từ 1 đến 65535.")
            self.port_entry.focus_set()
            return

        if not username:
            self.set_error("Vui lòng nhập tên Username của bạn.")
            self.user_entry.focus_set()
            return

        if len(username) < 3 or len(username) > 20:
            self.set_error("Username phải có độ dài từ 3 đến 20 ký tự.")
            self.user_entry.focus_set()
            return

        # Vô hiệu hóa nút trong khi chờ kết nối
        self.set_status("Đang kết nối tới Server...", "#1976D2")
        self.connect_btn.config(state=tk.DISABLED)

        # Gọi callback
        self.on_connect_callback(host, port, username)

    def set_status(self, text: str, color: str = "#2E7D32") -> None:
        """Cập nhật thông báo trạng thái."""
        self.status_lbl.config(text=text, foreground=color)

    def set_error(self, message: str) -> None:
        """Cập nhật thông báo lỗi."""
        self.status_lbl.config(text=f"⚠️ {message}", foreground="#D32F2F")
        self.connect_btn.config(state=tk.NORMAL)

    def enable_input(self) -> None:
        """Bật lại nút đăng nhập khi thất bại."""
        self.connect_btn.config(state=tk.NORMAL)
