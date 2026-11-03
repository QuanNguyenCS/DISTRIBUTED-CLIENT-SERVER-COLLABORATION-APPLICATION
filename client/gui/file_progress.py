"""
File: client/gui/file_progress.py
Mô tả: Hộp thoại / Khung hiển thị thanh tiến trình truyền file (File Transfer Progress Bar).
Hiển thị phần trăm (0-100%), kích thước, số chunks, tốc độ truyền và xác thực SHA-256.
"""

import time
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional


def format_bytes(num_bytes: int) -> str:
    """Định dạng số bytes thành chuỗi dung lượng dễ đọc (B, KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


class FileProgressDialog(tk.Toplevel):
    """
    Cửa sổ popup hiển thị tiến trình gửi hoặc nhận file qua socket TCP.
    """

    def __init__(
        self,
        parent: tk.Widget,
        title: str,
        file_name: str,
        file_size: int,
        total_chunks: int,
        direction: str = "upload",  # "upload" hoặc "download"
        on_cancel: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(parent)
        self.title(title)
        self.geometry("450x260")
        self.resizable(False, False)
        self.transient(parent)

        self.file_name = file_name
        self.file_size = file_size
        self.total_chunks = total_chunks
        self.direction = direction
        self.on_cancel = on_cancel

        self.start_time = time.time()
        self.is_completed = False

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        icon = "📤" if self.direction == "upload" else "📥"
        header_text = (
            f"{icon} Đang gửi file..."
            if self.direction == "upload"
            else f"{icon} Đang nhận file..."
        )
        self.header_lbl = ttk.Label(
            main_frame,
            text=header_text,
            font=("Segoe UI", 12, "bold"),
            foreground="#1976D2",
        )
        self.header_lbl.pack(anchor=tk.W, pady=(0, 10))

        # Tên file & Dung lượng
        self.info_lbl = ttk.Label(
            main_frame,
            text=f"Tập tin: {self.file_name} ({format_bytes(self.file_size)})",
            font=("Segoe UI", 9, "bold"),
        )
        self.info_lbl.pack(anchor=tk.W, pady=2)

        # Chunks & Tốc độ
        self.stats_lbl = ttk.Label(
            main_frame,
            text="Chuẩn bị truyền dữ liệu...",
            font=("Segoe UI", 8),
            foreground="#555555",
        )
        self.stats_lbl.pack(anchor=tk.W, pady=(0, 10))

        # Thanh tiến trình Progressbar
        self.progress_bar = ttk.Progressbar(
            main_frame,
            orient="horizontal",
            mode="determinate",
            maximum=100.0,
        )
        self.progress_bar.pack(fill=tk.X, pady=5)

        # Phần trăm label
        self.pct_lbl = ttk.Label(
            main_frame,
            text="0.0% (0 / 0 chunks)",
            font=("Segoe UI", 9, "bold"),
            foreground="#2E7D32",
        )
        self.pct_lbl.pack(anchor=tk.E, pady=(0, 15))

        # Nút hành động
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        self.action_btn = ttk.Button(
            btn_frame,
            text="Hủy truyền",
            command=self._on_close,
        )
        self.action_btn.pack(side=tk.RIGHT)

    def update_progress(self, chunks_sent: int, total_chunks: int, percent: float) -> None:
        """
        Cập nhật giao diện tiến trình (được gọi từ GUI main thread).
        """
        elapsed = max(time.time() - self.start_time, 0.001)
        bytes_transferred = int((percent / 100.0) * self.file_size)
        speed = bytes_transferred / elapsed  # bytes/sec

        self.progress_bar["value"] = percent
        self.pct_lbl.config(
            text=f"{percent:.1f}% ({chunks_sent}/{total_chunks} chunks)"
        )
        self.stats_lbl.config(
            text=f"Đã chuyển: {format_bytes(bytes_transferred)} / {format_bytes(self.file_size)} "
            f"| Tốc độ: {format_bytes(int(speed))}/s"
        )

    def set_completed(self, success: bool, message: str) -> None:
        """
        Đánh dấu hoàn tất quá trình truyền file.
        """
        self.is_completed = True
        self.progress_bar["value"] = 100.0 if success else self.progress_bar["value"]
        if success:
            self.header_lbl.config(
                text="✅ Truyền file THÀNH CÔNG (SHA-256 Verified)!",
                foreground="#2E7D32",
            )
            self.stats_lbl.config(text=message, foreground="#2E7D32")
        else:
            self.header_lbl.config(
                text="❌ Truyền file THẤT BẠI!",
                foreground="#D32F2F",
            )
            self.stats_lbl.config(text=message, foreground="#D32F2F")

        self.action_btn.config(text="Đóng", command=self.destroy)

    def _on_close(self) -> None:
        if not self.is_completed and self.on_cancel:
            self.on_cancel()
        self.destroy()
