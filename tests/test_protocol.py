"""
Unit Test: tests.test_protocol
Mô tả: Kiểm thử toàn diện cấu trúc gói tin (Packet Framing), hàm pack/unpack,
xử lý phân mảnh (fragmentation) và dính gói (concatenation) trong giao thức tầng ứng dụng.
"""

import json
import socket
import struct
import threading
import time
import pytest

from common.message_types import MessageType
from common.protocol import (
    FLAG_ENCRYPTED,
    FLAG_NONE,
    HEADER_SIZE,
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    ConnectionClosedError,
    InvalidMagicBytesError,
    Packet,
    PayloadTooLargeError,
    create_packet,
    recv_exact,
    recv_packet,
)


class TestPacketCreation:
    """Kiểm thử việc đóng gói nhị phân (create_packet)."""

    def test_create_packet_with_string_payload(self):
        text = "Xin chào Distributed System!"
        raw = create_packet(MessageType.CHAT_BROADCAST, text)

        # Header phải đúng 16 bytes
        assert len(raw) == HEADER_SIZE + len(text.encode("utf-8"))

        # Kiểm tra 2 bytes magic
        assert raw[:2] == MAGIC_BYTES

        # Kiểm tra version (byte thứ 3)
        assert raw[2] == PROTOCOL_VERSION

        # Kiểm tra message type (2 bytes: unsigned short)
        msg_type_unpacked = struct.unpack("!H", raw[3:5])[0]
        assert msg_type_unpacked == MessageType.CHAT_BROADCAST

    def test_create_packet_with_json_dict_payload(self):
        data = {"username": "alice", "action": "login", "room_id": 42}
        raw = create_packet(MessageType.AUTH_REQ, data, flags=FLAG_NONE)

        expected_payload_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
        assert len(raw) == HEADER_SIZE + len(expected_payload_bytes)

    def test_create_packet_with_empty_payload(self):
        raw = create_packet(MessageType.HEARTBEAT_PING, b"")
        assert len(raw) == HEADER_SIZE
        # Payload length ở 8 bytes cuối của header phải bằng 0
        payload_len = struct.unpack("!Q", raw[8:16])[0]
        assert payload_len == 0

    def test_create_packet_with_encrypted_flag(self):
        raw = create_packet(MessageType.CHAT_DIRECT, b"encrypted_bytes", flags=FLAG_ENCRYPTED)
        flag_byte = raw[5]
        assert flag_byte == FLAG_ENCRYPTED


class TestSocketPairTransmission:
    """Kiểm thử truyền nhận gói tin qua socket thực tế (dùng loopback socket pair)."""

    @pytest.fixture
    def sock_pair(self):
        """Khởi tạo một cặp socket TCP loopback kết nối với nhau."""
        # Trên Windows, socketpair() được hỗ trợ từ Python 3.5+
        server_sock, client_sock = socket.socketpair()
        yield server_sock, client_sock
        server_sock.close()
        client_sock.close()

    def test_send_and_recv_single_packet(self, sock_pair):
        server_sock, client_sock = sock_pair

        message = {"greeting": "Hello Server!", "code": 200}
        packet_bytes = create_packet(MessageType.CHAT_BROADCAST, message)
        client_sock.sendall(packet_bytes)

        received_pkt = recv_packet(server_sock)
        assert received_pkt.msg_type == MessageType.CHAT_BROADCAST
        assert received_pkt.to_json() == message
        assert not received_pkt.is_encrypted

    def test_tcp_concatenation_multiple_packets(self, sock_pair):
        """
        Kiểm thử hiện tượng dính gói (Packet Concatenation):
        Gửi liên tiếp 3 gói tin trong 1 lần send, bên nhận gọi recv_packet() 3 lần
        phải tách chính xác 3 gói tin không hề bị dính hay lẫn lộn.
        """
        server_sock, client_sock = sock_pair

        pkt1 = create_packet(MessageType.AUTH_REQ, {"user": "alice"})
        pkt2 = create_packet(MessageType.CHAT_BROADCAST, "Tin nhắn 1")
        pkt3 = create_packet(MessageType.CHAT_DIRECT, "Tin nhắn 2 bí mật")

        # Gửi dính liền toàn bộ 3 gói vào đường truyền TCP
        client_sock.sendall(pkt1 + pkt2 + pkt3)

        # Bên nhận lần lượt bóc tách từng gói
        res1 = recv_packet(server_sock)
        assert res1.msg_type == MessageType.AUTH_REQ
        assert res1.to_json() == {"user": "alice"}

        res2 = recv_packet(server_sock)
        assert res2.msg_type == MessageType.CHAT_BROADCAST
        assert res2.to_text() == "Tin nhắn 1"

        res3 = recv_packet(server_sock)
        assert res3.msg_type == MessageType.CHAT_DIRECT
        assert res3.to_text() == "Tin nhắn 2 bí mật"

    def test_tcp_fragmentation_packet_split(self, sock_pair):
        """
        Kiểm thử hiện tượng phân mảnh gói tin (Packet Fragmentation):
        Một gói tin 100 bytes bị chia nhỏ thành nhiều mảnh 2 bytes và gửi rải rác.
        Hàm recv_packet() phải tự động gom đủ và lắp ráp thành công gói tin.
        """
        server_sock, client_sock = sock_pair

        payload = {"data": "A" * 200, "status": "ok"}
        packet_bytes = create_packet(MessageType.FILE_OFFER_REQ, payload)

        def trickle_sender():
            # Chia nhỏ gói tin thành từng mẩu 7 bytes và gửi ngắt quãng
            chunk_size = 7
            for i in range(0, len(packet_bytes), chunk_size):
                client_sock.sendall(packet_bytes[i:i + chunk_size])
                time.sleep(0.005)  # Trì hoãn nhẹ 5ms mô phỏng mạng chập chờn

        sender_thread = threading.Thread(target=trickle_sender)
        sender_thread.start()

        # Bên nhận gọi recv_packet - hàm sẽ tự gom các mẩu cho tới khi đủ
        received_pkt = recv_packet(server_sock)
        sender_thread.join()

        assert received_pkt.msg_type == MessageType.FILE_OFFER_REQ
        assert received_pkt.to_json() == payload

    def test_invalid_magic_bytes_raises_error(self, sock_pair):
        """Nếu gửi gói tin có Magic Bytes lạ, bên nhận phải từ chối ngay lập tức."""
        server_sock, client_sock = sock_pair

        # Tạo gói tin nhưng cố tình sửa Magic Bytes thành "XX"
        corrupted = b"XX" + b"\x01\x00\x65\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        client_sock.sendall(corrupted)

        with pytest.raises(InvalidMagicBytesError):
            recv_packet(server_sock)

    def test_connection_closed_raises_error(self, sock_pair):
        """Khi client ngắt kết nối giữa chừng, recv_packet phải ném ConnectionClosedError."""
        server_sock, client_sock = sock_pair

        # Gửi dở 5 bytes header rồi đóng socket luôn
        client_sock.sendall(b"CA\x01\x00\x01")
        client_sock.close()

        with pytest.raises(ConnectionClosedError):
            recv_packet(server_sock)
