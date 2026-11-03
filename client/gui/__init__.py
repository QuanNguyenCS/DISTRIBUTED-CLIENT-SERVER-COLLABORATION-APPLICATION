"""
client/gui package
Giao diện người dùng đồ họa trực quan (GUI) xây dựng bằng Tkinter và ttk.
Áp dụng mô hình đa luồng kết hợp hàng đợi (Queue Pattern) chống treo giao diện (Zero UI Freeze).
"""

from client.gui.app import CollabChatApp

__all__ = ["CollabChatApp"]
