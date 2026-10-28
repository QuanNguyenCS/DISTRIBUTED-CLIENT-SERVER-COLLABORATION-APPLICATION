"""
Module: common.message_types
Mô tả: Định nghĩa các mã thông điệp (Message Types) cho giao thức tầng ứng dụng.
Mỗi loại thông điệp tương ứng với một hành vi/chức năng cụ thể trong hệ thống.
"""

from enum import IntEnum, unique


@unique
class MessageType(IntEnum):
    """
    Enum định nghĩa các mã loại thông điệp (Message Types).
    Sử dụng IntEnum để dễ dàng pack/unpack thành số nguyên 2 bytes (unsigned short).
    
    Phân nhóm mã theo dải số:
      - 100-199: Bắt tay & Xác thực (Handshake & Authentication)
      - 200-299: Quản lý người dùng & Trạng thái (User Discovery & Presence)
      - 300-399: Định tuyến tin nhắn trò chuyện (Chat Routing)
      - 400-499: Truyền tải file tin cậy (Reliable File Transfer)
      - 500-599: Giám sát kết nối & Nhịp tim (Heartbeat / Keepalive)
      - 600-699: Điều khiển kết nối & Ngắt kết nối (Connection Control)
    """

    # --- 100-199: Bắt tay & Xác thực ---
    HELLO_HANDSHAKE = 101       # Client gửi yêu cầu bắt tay phiên bản
    HANDSHAKE_ACK = 102         # Server phản hồi đồng ý bắt tay
    HANDSHAKE_REJECT = 103      # Server từ chối bắt tay (phiên bản không tương thích)
    AUTH_REQ = 104              # Client gửi yêu cầu đăng nhập (username)
    AUTH_RESP_SUCCESS = 105     # Server báo đăng nhập thành công
    AUTH_RESP_FAIL = 106        # Server báo đăng nhập thất bại (trùng tên, tên không hợp lệ)

    # --- 200-299: Quản lý người dùng & Trạng thái ---
    USER_LIST_REQ = 201         # Client yêu cầu lấy danh sách người dùng đang online
    USER_LIST_RESP = 202        # Server trả về danh sách người dùng
    USER_STATUS_BROADCAST = 203 # Server thông báo có user vừa JOINED hoặc LEFT

    # --- 300-399: Định tuyến tin nhắn trò chuyện ---
    CHAT_BROADCAST = 301        # Tin nhắn gửi đến toàn bộ phòng chat
    CHAT_DIRECT = 302           # Tin nhắn riêng tư 1-1 (Private Message)
    CHAT_ACK = 303              # Server hoặc bên nhận xác nhận đã nhận tin nhắn

    # --- 400-499: Truyền tải file tin cậy ---
    FILE_OFFER_REQ = 401        # Người gửi đề xuất gửi file (kèm tên file, dung lượng, sha256)
    FILE_OFFER_RESP = 402       # Người nhận/Server đồng ý (ACCEPT) hoặc từ chối (REJECT) nhận file
    FILE_CHUNK = 403            # Mảnh dữ liệu nhị phân của file (kèm chunk_id, offset, chunk_data)
    FILE_ACK = 404              # Xác nhận đã nhận được mảnh file hoặc hoàn tất toàn bộ file

    # --- 500-599: Giám sát kết nối & Nhịp tim ---
    HEARTBEAT_PING = 501        # Gói tin kiểm tra kết nối từ Client hoặc Server
    HEARTBEAT_PONG = 502        # Gói tin phản hồi xác nhận còn sống

    # --- 600-699: Điều khiển kết nối & Ngắt kết nối ---
    DISCONNECT_NOTICE = 601     # Thông báo chủ động ngắt kết nối (Graceful shutdown)
    ERROR_NOTICE = 602          # Thông báo lỗi giao thức hoặc lỗi hệ thống
