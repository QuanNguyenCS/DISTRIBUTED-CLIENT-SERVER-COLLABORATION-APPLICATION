"""
File: run_client.py
Mô tả: Entrypoint khởi chạy TCP Client với giao diện dòng lệnh (CLI).
Hỗ trợ kiến trúc 2 luồng: Luồng nền đón nhận tin nhắn từ Server và Luồng chính
nhập tin nhắn gửi đi trong thời gian thực.
Tích hợp quy trình xác thực người dùng và định tuyến tin nhắn:
  - Chat phòng chung (Broadcast)
  - Chat riêng tư 1-1 (Private Message / Unicast) với cú pháp @username hoặc /msg username
"""

import argparse
import sys
import time
from typing import Optional

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


def format_ts(ts: Optional[float] = None) -> str:
    """Định dạng dấu thời gian thành chuỗi HH:MM:SS."""
    if ts is None:
        ts = time.time()
    return time.strftime("%H:%M:%S", time.localtime(ts))


def handle_incoming_packet(packet: Packet) -> None:
    """Callback xử lý khi nhận được gói tin từ Server trả về."""
    msg_type = packet.msg_type

    if msg_type == MessageType.CHAT_BROADCAST:
        try:
            data = packet.to_json()
            sender = data.get("sender", "Hệ thống")
            content = data.get("content") or data.get("text", "")
            ts_str = format_ts(data.get("timestamp"))
            print(f"\n💬 [{ts_str}] [GLOBAL] {sender}: {content}\n> ", end="", flush=True)
        except Exception:
            print(f"\n💬 [Server]: {packet.to_text()}\n> ", end="", flush=True)

    elif msg_type == MessageType.CHAT_DIRECT:
        try:
            data = packet.to_json()
            sender = data.get("sender", "Ẩn danh")
            content = data.get("content") or data.get("text", "")
            ts_str = format_ts(data.get("timestamp"))
            print(f"\n🔒 [{ts_str}] [PRIVATE from {sender}]: {content}\n> ", end="", flush=True)
        except Exception:
            print(f"\n🔒 [PRIVATE]: {packet.to_text()}\n> ", end="", flush=True)

    elif msg_type == MessageType.CHAT_ACK:
        try:
            data = packet.to_json()
            recipient = data.get("recipient", "")
            content = data.get("content", "")
            ts_str = format_ts(data.get("timestamp"))
            print(f"\n📤 [{ts_str}] [PRIVATE to {recipient}]: {content}\n> ", end="", flush=True)
        except Exception:
            pass

    elif msg_type == MessageType.ERROR_NOTICE:
        try:
            data = packet.to_json()
            msg = data.get("message", "Lỗi không xác định.")
            print(f"\n⚠️ [Lỗi] {msg}\n> ", end="", flush=True)
        except Exception:
            print(f"\n⚠️ [Lỗi]: {packet.to_text()}\n> ", end="", flush=True)

    elif msg_type == MessageType.USER_STATUS_BROADCAST:
        try:
            data = packet.to_json()
            event = data.get("event")
            user = data.get("username")
            count = data.get("online_count", "?")
            ts_str = format_ts(data.get("timestamp"))
            if event == "JOINED":
                print(f"\n🔔 [{ts_str}] [Thông báo] '{user}' vừa tham gia! (Đang online: {count})\n> ", end="", flush=True)
            elif event == "LEFT":
                print(f"\n🔔 [{ts_str}] [Thông báo] '{user}' đã rời phòng! (Đang online: {count})\n> ", end="", flush=True)
        except Exception as e:
            logger.debug("Lỗi parse USER_STATUS_BROADCAST: %s", e)

    elif msg_type == MessageType.HEARTBEAT_PONG:
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
    parser.add_argument(
        "--passphrase",
        type=str,
        default=None,
        help="Mật khẩu mã hóa AES phòng chat (nếu có)",
    )
    parser.add_argument(
        "--p2p-port",
        type=int,
        default=0,
        help="Cổng TCP lắng nghe kết nối nhận file P2P trực tiếp (mặc định 0 để OS tự cấp)",
    )

    args = parser.parse_args()

    print("=" * 65)
    print(" DISTRIBUTED CLIENT-SERVER COLLABORATION APPLICATION - CLIENT")
    print("=" * 65)

    client = ClientCore(
        server_host=args.host,
        server_port=args.port,
        client_name=args.username or "Guest-Client",
        p2p_port=args.p2p_port,
    )
    if args.passphrase:
        client.enable_encryption(args.passphrase)

    # Đăng ký callbacks xử lý các sự kiện đến từ Server
    client.register_callback(MessageType.CHAT_BROADCAST, handle_incoming_packet)
    client.register_callback(MessageType.CHAT_DIRECT, handle_incoming_packet)
    client.register_callback(MessageType.CHAT_ACK, handle_incoming_packet)
    client.register_callback(MessageType.ERROR_NOTICE, handle_incoming_packet)
    client.register_callback(MessageType.USER_STATUS_BROADCAST, handle_incoming_packet)
    client.register_callback(MessageType.HEARTBEAT_PONG, handle_incoming_packet)

    # Đăng ký callback khi nhận file thành công
    def on_received_file(sender: str, file_name: str, save_path: str):
        print(f"\n📁 [File Nhận Được] Bạn vừa nhận được file '{file_name}' từ '{sender}'! Đã lưu tại: {save_path}\n> ", end="", flush=True)

    client.on_file_received = on_received_file

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
                p2p_info = f" | Cổng P2P nhận file: {client.p2p_port}" if client.p2p_port else ""
                print(f"✅ {msg} Chào mừng '{client.username}' tham gia phòng hợp tác!{p2p_info}")
                users = client.online_users or [client.username]
                print(f"👥 Danh sách đang online ({len(users)}): {', '.join(users)}")
            else:
                print(f"❌ {msg} Vui lòng chọn một Username khác.")

        if not client.is_connected:
            return

        print("-" * 65)
        print("  HƯỚNG DẪN TRÒ CHUYỆN:")
        print("  - Gõ tin nhắn và Enter để chat phòng chung (Broadcast).")
        print("  - Gõ '@<username> <nội dung>' hoặc '/msg <username> <nội dung>' để chat riêng 1-1.")
        print("  - Gõ '/file <username> <đường_dẫn>' để gửi file tin cậy (kèm SHA-256).")
        print("  - Gõ '/users' hoặc '/who' để xem danh sách đang online.")
        print("  - Gõ '/ping' để kiểm tra nhịp tim (Keepalive).")
        print("  - Gõ '/quit' hoặc '/exit' để đăng xuất và thoát an toàn.")
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
            elif user_input.startswith("@"):
                # Chat riêng theo cú pháp: @username nội dung
                parts = user_input[1:].split(maxsplit=1)
                if len(parts) == 2:
                    target_user, direct_text = parts
                    client.send_direct_message(target_user.strip(), direct_text.strip())
                else:
                    print("⚠️ Cú pháp chat riêng: @<username> <nội dung>")
            elif cmd_lower.startswith("/msg ") or cmd_lower.startswith("/dm "):
                # Chat riêng theo cú pháp: /msg username nội dung
                parts = user_input.split(maxsplit=2)
                if len(parts) == 3:
                    _, target_user, direct_text = parts
                    client.send_direct_message(target_user.strip(), direct_text.strip())
                else:
                    print("⚠️ Cú pháp chat riêng: /msg <username> <nội dung>")
            elif cmd_lower.startswith("/file ") or cmd_lower.startswith("/sendfile "):
                # Gửi file theo cú pháp: /file username đường_dẫn_file
                parts = user_input.split(maxsplit=2)
                if len(parts) == 3:
                    _, target_user, file_path = parts
                    print(f"🚀 Bắt đầu gửi file '{file_path}' tới '{target_user}'...")
                    def cli_progress(sent, total, pct):
                        print(f"\r🚀 Đang truyền: {sent}/{total} chunks ({pct:.1f}%)...", end="", flush=True)
                    ok, msg = client.send_file(target_user.strip(), file_path.strip(), progress_callback=cli_progress)
                    print()
                    if ok:
                        print(f"✅ {msg}")
                    else:
                        print(f"❌ {msg}")
                else:
                    print("⚠️ Cú pháp gửi file: /file <username> <đường_dẫn_file>")
            else:
                # Chat phòng chung
                client.send_broadcast(user_input)

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
