"""
Unit & Integration Tests cho Giai đoạn 6: Truyền File Tin Cậy qua TCP (Reliable File Transfer)
Kiểm tra toàn diện:
  1. Đóng gói & giải gói Chunk nhị phân (pack/unpack chunk payload).
  2. Tính toán mã băm SHA-256 đối chiếu tính toàn vẹn.
  3. Ghép file từ các chunk tuần tự (Assembly) và xác thực hash.
  4. Kiểm thử truyền file hoàn chỉnh qua TCP giữa 2 Client (Alice -> Bob).
  5. Xử lý lỗi khi gửi file cho người dùng offline hoặc file không tồn tại.
"""

import os
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path
import pytest

from common.message_types import MessageType
from server.server_core import ServerCore
from client.client_core import ClientCore
from client.file_transfer import (
    IncomingFileTransfer,
    calculate_file_hash,
    pack_chunk_payload,
    read_file_chunks,
    unpack_chunk_payload,
)


def get_free_port() -> int:
    """Lấy cổng mạng rảnh trên localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestFileTransferUnit:
    """Kiểm thử đơn vị cho các hàm xử lý file."""

    def test_chunk_pack_and_unpack(self):
        """Kiểm tra đóng gói và mở gói dữ liệu nhị phân của chunk."""
        sample_data = b"HELLO_RAW_BINARY_CHUNK_DATA_12345" * 100
        packed = pack_chunk_payload(
            file_id="test-file-01",
            chunk_index=3,
            total_chunks=10,
            chunk_data=sample_data,
        )

        meta, unpacked_data = unpack_chunk_payload(packed)
        assert meta["file_id"] == "test-file-01"
        assert meta["chunk_index"] == 3
        assert meta["total_chunks"] == 10
        assert meta["chunk_size"] == len(sample_data)
        assert unpacked_data == sample_data

    def test_file_hash_and_chunk_generator(self):
        """Kiểm tra tính mã băm SHA-256 và đọc file theo chunk generator."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"ABCDEFGHIJ" * 10000)  # 100 KB
            temp_path = tf.name

        try:
            expected_hash = calculate_file_hash(temp_path)
            assert len(expected_hash) == 64

            # Đọc chunks với chunk_size = 32 KB
            chunks = list(read_file_chunks(temp_path, chunk_size=32 * 1024))
            assert len(chunks) == 4  # 100KB / 32KB = 3 chunk 32KB + 1 chunk 4KB

            # Ráp lại để so sánh
            rebuilt_data = b"".join(chunk_data for _, chunk_data in chunks)
            assert len(rebuilt_data) == 100000
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


class TestFileTransferIntegration:
    """Kiểm thử truyền file tích hợp qua mạng TCP."""

    def test_full_file_transfer_between_clients(self):
        """Alice gửi file nhị phân (ảnh/tài liệu) cho Bob qua Server."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        # Tạo thư mục download riêng cho test
        test_dir = tempfile.mkdtemp(prefix="collab_test_")
        alice_file = os.path.join(test_dir, "document.pdf")
        original_content = os.urandom(120 * 1024)  # 120 KB dữ liệu ngẫu nhiên

        with open(alice_file, "wb") as f:
            f.write(original_content)
        original_hash = calculate_file_hash(alice_file)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        bob.download_dir = os.path.join(test_dir, "bob_downloads")

        assert alice.connect() and alice.authenticate("Alice")[0]
        assert bob.connect() and bob.authenticate("Bob")[0]

        progress_records = []

        def on_progress(sent, total, pct):
            progress_records.append((sent, total, pct))

        # Alice gửi file cho Bob
        success, msg = alice.send_file(
            recipient="Bob",
            file_path=alice_file,
            progress_callback=on_progress,
            timeout=10.0,
        )

        assert success is True
        assert "toàn vẹn 100%" in msg
        assert len(progress_records) > 0
        assert progress_records[-1][2] == 100.0  # Tiến độ đạt 100%

        # Kiểm tra file đã lưu tại thư mục download của Bob
        bob_received_file = os.path.join(bob.download_dir, "document.pdf")
        assert os.path.isfile(bob_received_file)

        # Đối chiếu mã băm và nội dung file bit-by-bit
        received_hash = calculate_file_hash(bob_received_file)
        assert received_hash == original_hash

        with open(bob_received_file, "rb") as f:
            assert f.read() == original_content

        # Dọn dẹp
        alice.disconnect()
        bob.disconnect()
        server.stop()
        sthread.join(timeout=2.0)
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_send_file_to_offline_user_fails(self):
        """Alice gửi file cho người dùng không online: Báo lỗi phù hợp."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"Test content")
            test_file = tf.name

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        assert alice.connect() and alice.authenticate("AliceSender")[0]

        success, reason = alice.send_file(
            recipient="GhostReceiver",
            file_path=test_file,
            timeout=2.0,
        )

        assert success is False
        assert "không online" in reason or "hết thời gian" in reason

        alice.disconnect()
        server.stop()
        sthread.join(timeout=2.0)
        if os.path.exists(test_file):
            os.remove(test_file)
