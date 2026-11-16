"""
File: tests/test_gui.py
Mô tả: Unit tests kiểm tra việc khởi tạo các thành phần giao diện đồ họa Tkinter (GUI):
LoginView, ChatView, FileProgressDialog và CollabChatApp.
"""

import gc
import unittest
from unittest.mock import MagicMock

import pytest

tk = pytest.importorskip("tkinter", reason="Tkinter chưa được cài đặt trong môi trường Python này")

from client.gui.chat_view import ChatView
from client.gui.file_progress import FileProgressDialog, format_bytes
from client.gui.login_view import LoginView
from client.gui.app import CollabChatApp


class TestGuiComponents(unittest.TestCase):
    """Kiểm thử khởi tạo và logic nội bộ của các Widget GUI."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.app = CollabChatApp()
            cls.app.withdraw()  # Ẩn cửa sổ khi chạy test
            cls.root = cls.app
        except tk.TclError:
            # Môi trường không có DISPLAY / headless
            cls.app = None
            cls.root = None

    @classmethod
    def tearDownClass(cls):
        if cls.app:
            cls.app.destroy()
            cls.app = None
            cls.root = None
        gc.collect()

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
        cb_mock.assert_called_once_with("127.0.0.1", 9000, "TestUser")
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
        self.app._show_login_view()
        self.app.update_idletasks()
        self.assertIsNotNone(self.app.login_view)

    def test_gui_queue_event_dispatching(self):
        """Kiểm tra cơ chế Producer-Consumer Queue (_process_gui_queue & _dispatch_gui_event) xử lý sự kiện mạng an toàn."""
        app = self.app
        app.current_username = "Alice"
        app.gui_queue.put(("login_success", "Alice"))
        app._process_gui_queue()
        app.update_idletasks()
        self.assertIsNotNone(app.chat_view)

        # 1. Nhận tin nhắn Broadcast qua gui_queue
        app.gui_queue.put(
            ("chat_broadcast", {"sender": "Bob", "content": "Hello qua Queue!", "timestamp": 1710000000.0})
        )
        # 2. Nhận tin nhắn Direct 1-1 qua gui_queue -> tự tạo tab user_bob
        app.gui_queue.put(
            ("chat_direct", {"sender": "Bob", "recipient": "Alice", "content": "Tin riêng qua Queue", "timestamp": 1710000005.0})
        )
        # 3. Nhận thông báo file lỗi (P2P fail) qua gui_queue -> hiện cảnh báo trong tab user_bob
        app.gui_queue.put(
            ("file_send_finished", ("fid01", False, "Không thể kết nối P2P", "Bob", "report.pdf"))
        )
        # 4. Nhận sự kiện user_status (JOINED rồi LEFT) -> Listbox tự động cập nhật không cần bấm Làm mới
        app.gui_queue.put(
            ("user_status", {"event": "JOINED", "username": "Bob", "online_users": ["Alice", "Bob"]})
        )
        app._process_gui_queue()
        app.update_idletasks()
        self.assertEqual(app.chat_view.online_users_list, ["Alice", "Bob"])

        app.gui_queue.put(
            ("user_status", {"event": "LEFT", "username": "Bob", "online_users": ["Alice"]})
        )
        app._process_gui_queue()
        app.update_idletasks()
        self.assertEqual(app.chat_view.online_users_list, ["Alice"])

        global_text = app.chat_view.chat_tabs["global"].get("1.0", tk.END)
        self.assertIn("Hello qua Queue!", global_text)

        self.assertIn("user_bob", app.chat_view.chat_tabs)
        bob_tab_text = app.chat_view.chat_tabs["user_bob"].get("1.0", tk.END)
        self.assertIn("Tin riêng qua Queue", bob_tab_text)
        self.assertIn("report.pdf", bob_tab_text)
        self.assertIn("thất bại", bob_tab_text)

        # F13: Đăng xuất -> reset chat_view = None; các gói tin đến muộn qua queue không làm văng TclError
        app._on_logout()
        self.assertIsNone(app.chat_view)
        app.gui_queue.put(("chat_broadcast", {"sender": "LateUser", "content": "Late msg"}))
        app.gui_queue.put(("user_status", {"event": "LEFT", "username": "Bob", "online_users": []}))
        app._process_gui_queue()
        app.update_idletasks()


