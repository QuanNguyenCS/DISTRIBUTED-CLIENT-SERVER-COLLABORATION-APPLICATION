"""
File: run_server.py
Mô tả: Entrypoint khởi chạy TCP Server cho ứng dụng phân tán.
Hỗ trợ tham số dòng lệnh --host và --port.
"""

import argparse
import sys

# Đảm bảo console Windows in đúng tiếng Việt UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from common.logger import get_logger
from server.server_core import ServerCore

logger = get_logger("run_server")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Khởi chạy Collaboration TCP Server"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Địa chỉ IP để bind (Mặc định: 0.0.0.0 - Lắng nghe tất cả card mạng)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="Cổng kết nối TCP (Mặc định: 9000)",
    )
    parser.add_argument(
        "--server-id",
        type=str,
        default="CollabServer-Alpha",
        help="Mã định danh của Server (Mặc định: CollabServer-Alpha)",
    )
    parser.add_argument(
        "--passphrase",
        type=str,
        default=None,
        help="Mật khẩu mã hóa AES phòng chat (nếu có)",
    )

    args = parser.parse_args()

    print("=" * 65)
    print(" DISTRIBUTED CLIENT-SERVER COLLABORATION APPLICATION - SERVER")
    print("=" * 65)

    server = ServerCore(host=args.host, port=args.port, server_id=args.server_id)
    if args.passphrase:
        server.enable_encryption(args.passphrase)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Chương trình kết thúc bởi người dùng.")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
