"""
File: run_gui.py
Mô tả: Điểm khởi chạy (Entrypoint) ứng dụng Client với giao diện đồ họa trực quan (Tkinter GUI).
Hỗ trợ đầy đủ: Chat nhóm (Broadcast), Chat riêng 1-1 theo tab, Truyền file kèm thanh tiến trình và Mã hóa AES.
"""

import sys

# Đảm bảo console in đúng tiếng Việt UTF-8 trên Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from client.gui.app import CollabChatApp


def main() -> None:
    """Khởi động ứng dụng GUI Tkinter."""
    app = CollabChatApp()
    app.mainloop()


if __name__ == "__main__":
    main()
