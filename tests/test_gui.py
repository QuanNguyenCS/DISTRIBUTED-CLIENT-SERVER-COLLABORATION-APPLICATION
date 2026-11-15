"""
File: tests/test_gui.py
Mô tả: Unit tests kiểm tra việc khởi tạo các thành phần giao diện đồ họa Tkinter (GUI):
LoginView, ChatView, FileProgressDialog và CollabChatApp.
"""

import tkinter as tk
import unittest
from unittest.mock import MagicMock

from client.gui.chat_view import ChatView
from client.gui.file_progress import FileProgressDialog, format_bytes
from client.gui.login_view import LoginView
from client.gui.app import CollabChatApp


class TestGuiComponents(unittest.TestCase):
    """Kiểm thử khởi tạo và logic nội bộ của các Widget GUI."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.root = tk.Tk()
            cls.root.withdraw()  # Ẩn cửa sổ khi chạy test
        except tk.TclError:
            # Môi trường không có DISPLAY / headless
            cls.root = None

    @classmethod
    def tearDownClass(cls):
        if cls.root:
            cls.root.destroy()

    def setUp(self):
        if not self.root:
            self.skipTest("Tkinter không khả dụng trên môi trường không có DISPLAY")

    def test_format_bytes(self):
        """Kiểm tra hàm format_bytes định dạng chính xác."""
        self.assertEqual(format_bytes(500), "500.0 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1024 * 1024), "1.0 MB")
        self.assertEqual(format_bytes(1024 * 1024 * 1024 * 2), "2.0 GB")

    def test_login_view_initialization(self):
        """Khởi tạo LoginView và kiểm tra các trường nhập liệu."""
        cb_mock = MagicMock()
        login_view = LoginView(self.root, on_connect=cb_mock)
        login_view.pack()
        self.root.update_idletasks()

        self.assertEqual(login_view.host_var.get(), "127.0.0.1")
        self.assertEqual(login_view.port_var.get(), "9000")

        # Thử submit khi chưa nhập username
        login_view.user_var.set("")
        login_view._on_submit()
        cb_mock.assert_not_called()

        # Nhập username hợp lệ và submit
        login_view.user_var.set("TestUser")
        login_view._on_submit()
        cb_mock.assert_called_once_with("127.0.0.1", 9000, "TestUser", None)
        login_view.destroy()

    def test_chat_view_tabs_and_messages(self):
        """Khởi tạo ChatView, thêm tab riêng và ghi nhận tin nhắn."""
        chat_view = ChatView(
            self.root,
            current_username="Alice",
            on_send_broadcast=MagicMock(),
            on_send_direct=MagicMock(),
            on_send_file=MagicMock(),
            on_refresh_users=MagicMock(),
            on_logout=MagicMock(),
            is_encrypted=True,
        )
        chat_view.pack()
        self.root.update_idletasks()

        # Cập nhật danh sách online
        chat_view.update_online_users(["Alice", "Bob", "Charlie"])
        self.assertEqual(len(chat_view.online_users_list), 3)

        # Ghi tin nhắn vào phòng chung
        chat_view.append_message("global", "Bob", "Xin chào phòng chung!")
        text_widget = chat_view.chat_tabs["global"]
        content = text_widget.get("1.0", tk.END)
        self.assertIn("Bob", content)
        self.assertIn("Xin chào phòng chung!", content)

        # Mở tab chat riêng với Bob
        chat_view.get_or_create_direct_tab("Bob")
        self.assertIn("user_bob", chat_view.chat_tabs)

        chat_view.append_message("user_bob", "Bob", "Tin mật riêng tư", is_self=False)
        bob_text = chat_view.chat_tabs["user_bob"].get("1.0", tk.END)
        self.assertIn("Tin mật riêng tư", bob_text)

        chat_view.destroy()

    def test_file_progress_dialog(self):
        """Khởi tạo và cập nhật thanh tiến trình file."""
        dlg = FileProgressDialog(
            parent=self.root,
            title="Gửi file test",
            file_name="demo.zip",
            file_size=1024 * 1024,
            total_chunks=32,
            direction="upload",
        )
        self.root.update_idletasks()

        # Cập nhật tiến trình lên 50%
        dlg.update_progress(16, 32, 50.0)
        self.assertEqual(dlg.progress_bar["value"], 50.0)

        # Đánh dấu hoàn tất
        dlg.set_completed(True, "File đã gửi xong!")
        self.assertTrue(dlg.is_completed)
        self.assertEqual(dlg.progress_bar["value"], 100.0)
        dlg.destroy()

    def test_chat_view_double_click_open_direct_tab(self):
        """Chọn user trong Listbox và gọi _open_selected_user_chat không gây TclError và chuyển đúng tab."""
        chat_view = ChatView(
            self.root,
            current_username="Alice",
            on_send_broadcast=MagicMock(),
            on_send_direct=MagicMock(),
            on_send_file=MagicMock(),
            on_refresh_users=MagicMock(),
            on_logout=MagicMock(),
            is_encrypted=True,
        )
        chat_view.pack()
        chat_view.update_online_users(["Alice", "Bob", "Charlie"])
        self.root.update_idletasks()

        bob_idx = None
        for idx in range(chat_view.users_listbox.size()):
            if "Bob" in chat_view.users_listbox.get(idx):
                bob_idx = idx
                break
        self.assertIsNotNone(bob_idx)

        chat_view.users_listbox.selection_clear(0, tk.END)
        chat_view.users_listbox.selection_set(bob_idx)
        chat_view._open_selected_user_chat()
        self.root.update_idletasks()

        self.assertIn("user_bob", chat_view.chat_tabs)
        self.assertIn("user_bob", chat_view.tab_frames)
        self.assertEqual(chat_view._get_current_active_tab_id(), "user_bob")
        self.assertEqual(chat_view._get_recipient_for_tab("user_bob"), "Bob")
        chat_view.destroy()

    def test_collab_chat_app_initialization(self):
        """Khởi tạo App root window."""
        app = CollabChatApp()
        app.update_idletasks()
        self.assertIsNotNone(app.login_view)
        app.destroy()
