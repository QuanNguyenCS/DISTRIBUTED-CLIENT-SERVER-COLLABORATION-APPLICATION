"""
File: run_client.py
Mô tả: Entrypoint khởi chạy TCP Client với giao diện dòng lệnh (CLI).
Hỗ trợ kiến trúc 2 luồng: Luồng nền đón nhận tin nhắn từ Server và Luồng chính
nhập tin nhắn gửi đi trong thời gian thực.
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


def handle_incoming_message(packet: Packet) -> None:
    """Callback xử lý khi nhận được gói tin từ Server trả về."""
    if packet.msg_type == MessageType.CHAT_BROADCAST:
        try:
            data = packet.to_json()
            sender = data.get("sender", "Hệ thống")
            text = data.get("text", "")
            print(f"\n💬 [{sender}]: {text}\n> ", end="", flush=True)
        except Exception:
            print(f"\n💬 [Server]: {packet.to_text()}\n> ", end="", flush=True)

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
        "--name",
        type=str,
        default=None,
        help="Tên định danh của Client (Mặc định: Alice/Bob ngẫu nhiên)",
    )

    args = parser.parse_args()

    # Nếu không nhập tên, tạo tên mặc định kèm thời gian
    client_name = args.name or f"User-{int(time.time()) % 1000}"

    print("=" * 65)
    print(f" DISTRIBUTED COLLABORATION CLIENT: [{client_name}]")
    print("=" * 65)

    client = ClientCore(
        server_host=args.host,
        server_port=args.port,
        client_name=client_name,
    )

    # Đăng ký callback nhận tin nhắn từ Server
    client.register_callback(MessageType.CHAT_BROADCAST, handle_incoming_message)
    client.register_callback(MessageType.HEARTBEAT_PONG, handle_incoming_message)

    try:
        success = client.connect(timeout=5.0)
        if not success:
            logger.error("❌ Không thể hoàn tất bắt tay với Server.")
            sys.exit(1)

        print("-" * 65)
        print("  ĐÃ KẾT NỐI TỚI SERVER THÀNH CÔNG!")
        print("  - Gõ nội dung tin nhắn bất kỳ và nhấn Enter để gửi.")
        print("  - Gõ '/ping' để gửi kiểm tra nhịp tim (Heartbeat).")
        print("  - Gõ '/quit' hoặc '/exit' để ngắt kết nối an toàn.")
        print("-" * 65)

        # Luồng chính đọc lệnh từ bàn phím
        while client.is_connected:
            try:
                user_input = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not user_input:
                continue

            if user_input.lower() in ("/quit", "/exit"):
                print("Đang thoát chương trình...")
                break
            elif user_input.lower() == "/ping":
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
        print("Tạm biệt!")


if __name__ == "__main__":
    main()
