"""
Module: common.logger
Mô tả: Cấu hình hệ thống ghi log (Logging) chuẩn hóa cho toàn ứng dụng.
Hỗ trợ định dạng thời gian chuẩn xác, phân cấp độ log (INFO, DEBUG, WARNING, ERROR)
và định dạng màu sắc trên terminal để dễ quan sát khi gỡ lỗi.
"""

import logging
import sys

# Đảm bảo mã hóa UTF-8 trên Windows console để không bị UnicodeEncodeError với tiếng Việt & emoji
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


class ColoredFormatter(logging.Formatter):
    """Bộ định dạng log có màu sắc cho console."""

    # ANSI escape sequences
    GRAY = "\033[90m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD_RED = "\033[1;91m"
    RESET = "\033[0m"

    LEVEL_COLORS = {
        logging.DEBUG: GRAY,
        logging.INFO: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: BOLD_RED,
    }

    def __init__(self) -> None:
        super().__init__()
        self._formatters = {
            lvl: logging.Formatter(
                f"{self.GRAY}%(asctime)s{self.RESET} | "
                f"{color}%(levelname)-8s{self.RESET} | "
                f"{self.CYAN}%(name)s{self.RESET} | "
                f"%(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            for lvl, color in self.LEVEL_COLORS.items()
        }
        self._default_formatter = logging.Formatter(
            f"{self.GRAY}%(asctime)s{self.RESET} | "
            f"{self.RESET}%(levelname)-8s{self.RESET} | "
            f"{self.CYAN}%(name)s{self.RESET} | "
            f"%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        formatter = self._formatters.get(record.levelno, self._default_formatter)
        return formatter.format(record)


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Lấy hoặc khởi tạo một logger với định dạng chuẩn của ứng dụng.

    Args:
        name: Tên của module gọi log (ví dụ: 'server.core', 'client.core').
        level: Cấp độ log tối thiểu (mặc định: logging.INFO).

    Returns:
        logging.Logger: Đối tượng logger đã cấu hình handler.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Tránh gắn lặp handler nếu get_logger được gọi nhiều lần cùng 1 tên
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(ColoredFormatter())
        logger.addHandler(console_handler)

    logger.propagate = False
    return logger
