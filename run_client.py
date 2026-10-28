"""
File: run_client.py
Mô tả: Entrypoint khởi chạy TCP Client thử nghiệm kết nối và bắt tay với Server.
Hỗ trợ tham số dòng lệnh --host, --port và --name.
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
from client.client_core import ClientCore

logger = get_logger("run_client")


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
        default="Alice-Client",
        help="Tên định danh của Client (Mặc định: Alice-Client)",
    )

    args = parser.parse_args()

    print("=" * 65)
    print(" DISTRIBUTED CLIENT-SERVER COLLABORATION APPLICATION - CLIENT")
    print("=" * 65)

    client = ClientCore(
        server_host=args.host,
        server_port=args.port,
        client_name=args.name,
    )

    try:
        success = client.connect(timeout=5.0)
        if success:
            logger.info("🎉 Kết nối và bắt tay hoàn tất!")
            logger.info("Thông tin Server nhận được: %s", client.server_info)
            # Giữ kết nối một lúc để mô phỏng hoạt động rồi ngắt kết nối
            time.sleep(1.0)
        else:
            logger.error("❌ Không thể hoàn tất bắt tay với Server.")
    except ConnectionRefusedError:
        logger.error("Không thể kết nối: Server chưa chạy tại %s:%d.", args.host, args.port)
        sys.exit(1)
    except Exception as exc:
        logger.error("Lỗi ngoại lệ: %s", exc)
        sys.exit(1)
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
