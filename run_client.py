"""
File: run_client.py
Mô tả: Entrypoint khởi chạy TCP Client với giao diện dòng lệnh (CLI).
Hỗ trợ kiến trúc 2 luồng: Luồng nền đón nhận tin nhắn từ Server và Luồng chính
nhập tin nhắn gửi đi trong thời gian thực.
Tích hợp quy trình xác thực người dùng (Auth) và quản lý trạng thái online/offline.
"""

import argparse
import sys
import time

# Đảm bảo console Windows in đúng tiếng Việt UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from common.logger import get_logger
from common.message_types import MessageType
from common.protocol import Packet
from client.client_core import ClientCore

logger = get_logger("run_client")


def handle_incoming_packet(packet: Packet) -> None:
    """Callback xử lý khi nhận được gói tin từ Server trả về."""
    if packet.msg_type == MessageType.CHAT_BROADCAST:
        try:
            data = packet.to_json()
            sender = data.get("sender", "Hệ thống")
            text = data.get("text", "")
            print(f"\n💬 [{sender}]: {text}\n> ", end="", flush=True)
        except Exception:
            print(f"\n💬 [Server]: {packet.to_text()}\n> ", end="", flush=True)

    elif packet.msg_type == MessageType.USER_STATUS_BROADCAST:
        try:
            data = packet.to_json()
            event = data.get("event")
            user = data.get("username")
            count = data.get("online_count", "?")
            if event == "JOINED":
                print(f"\n🔔 [Thông báo] Người dùng '{user}' vừa tham gia! (Đang online: {count})\n> ", end="", flush=True)
            elif event == "LEFT":
                print(f"\n🔔 [Thông báo] Người dùng '{user}' đã rời phòng! (Đang online: {count})\n> ", end="", flush=True)
        except Exception as e:
            logger.debug("Lỗi parse USER_STATUS_BROADCAST: %s", e)

    elif packet.msg_type == MessageType.HEARTBEAT_PONG:
        logger.debug("Nhận phản hồi nhịp tim (PONG) từ Server.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Khởi chạy Collaboration TCP Client"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Địa chỉ IP của Server (Mặc định: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="Cổng kết nối TCP của Server (Mặc định: 9000)",
    )
    parser.add_argument(
        "--username",
        "--name",
        dest="username",
        type=str,
        default=None,
        help="Tên đăng nhập của người dùng (3-20 ký tự, không dấu cách)",
    )

    args = parser.parse_args()

    print("=" * 65)
    print(" DISTRIBUTED CLIENT-SERVER COLLABORATION APPLICATION - CLIENT")
    print("=" * 65)

    client = ClientCore(
        server_host=args.host,
        server_port=args.port,
        client_name=args.username or "Guest-Client",
    )

    # Đăng ký callbacks xử lý các sự kiện đến từ Server
    client.register_callback(MessageType.CHAT_BROADCAST, handle_incoming_packet)
    client.register_callback(MessageType.USER_STATUS_BROADCAST, handle_incoming_packet)
    client.register_callback(MessageType.HEARTBEAT_PONG, handle_incoming_packet)

    try:
        # 1. Kết nối và thực hiện Handshake TCP
        success = client.connect(timeout=5.0)
        if not success:
            logger.error("❌ Không thể hoàn tất bắt tay với Server.")
            sys.exit(1)

        print("-" * 65)
        print("  🔗 KẾT NỐI TỚI SERVER THÀNH CÔNG! VUI LÒNG ĐĂNG NHẬP.")
        print("-" * 65)

        # 2. Quy trình xác thực người dùng (Authentication)
        initial_username = args.username
        while client.is_connected and not client.is_authenticated:
            if initial_username:
                chosen_user = initial_username
                initial_username = None  # Chỉ thử 1 lần từ dòng lệnh
            else:
                try:
                    chosen_user = input("👉 Nhập Username của bạn (hoặc /quit để thoát): ").strip()
                except (EOFError, KeyboardInterrupt):
                    client.disconnect()
                    sys.exit(0)

            if not chosen_user:
                continue

            if chosen_user.lower() in ("/quit", "/exit"):
                client.disconnect()
                sys.exit(0)

            ok, msg = client.authenticate(chosen_user)
            if ok:
                print(f"✅ {msg} Chào mừng '{client.username}' tham gia phòng hợp tác!")
                users = client.online_users or [client.username]
                print(f"👥 Danh sách đang online ({len(users)}): {', '.join(users)}")
            else:
                print(f"❌ {msg} Vui lòng chọn một Username khác.")

        if not client.is_connected:
            return

        print("-" * 65)
        print("  CÁC LỆNH HỖ TRỢ:")
        print("  - Gõ văn bản bất kỳ và nhấn Enter để chat trong phòng chung.")
        print("  - Gõ '/users' hoặc '/who' để cập nhật danh sách người dùng online.")
        print("  - Gõ '/ping' để kiểm tra nhịp tim (Keepalive).")
        print("  - Gõ '/quit' hoặc '/exit' để đăng xuất và ngắt kết nối an toàn.")
        print("-" * 65)

        # 3. Vòng lặp đọc lệnh và tin nhắn từ bàn phím
        while client.is_connected:
            try:
                user_input = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not user_input:
                continue

            cmd_lower = user_input.lower()

            if cmd_lower in ("/quit", "/exit"):
                print("Đang đăng xuất và thoát chương trình...")
                break
            elif cmd_lower in ("/users", "/who"):
                users = client.request_user_list()
                if users is not None:
                    print(f"👥 Danh sách người dùng online ({len(users)}): {', '.join(users)}")
                else:
                    print("⚠️ Không thể lấy danh sách người dùng vào lúc này.")
            elif cmd_lower == "/ping":
                client.send_heartbeat()
                print("Đã gửi PING lên Server...")
            else:
                client.send_chat(user_input)

    except ConnectionRefusedError:
        logger.error("Không thể kết nối: Server chưa chạy tại %s:%d.", args.host, args.port)
        sys.exit(1)
    except Exception as exc:
        logger.error("Lỗi ngoại lệ: %s", exc)
        sys.exit(1)
    finally:
        client.disconnect()
        print("Tạm biệt! Hẹn gặp lại.")


if __name__ == "__main__":
    main()
