"""
Unit & Integration Tests cho Giai đoạn 5: Định tuyến Tin nhắn Thời gian thực (Broadcast & Private Messaging)
Kiểm tra toàn diện:
  1. Chat phòng chung (Broadcast Routing): Tin nhắn từ 1 client được chuyển tiếp tới tất cả client khác.
  2. Chat riêng 1-1 (Unicast / Direct Routing): Tin nhắn chỉ tới đúng người nhận mục tiêu,
     người thứ 3 hoàn toàn không nhận được gói tin này.
  3. Xác nhận đã gửi tin riêng thành công (CHAT_ACK).
  4. Xử lý lỗi khi gửi tin riêng tới người dùng offline / không tồn tại (ERROR_NOTICE: USER_NOT_FOUND).
  5. Xử lý lỗi khi cố tình gửi tin riêng cho chính mình (ERROR_NOTICE: SELF_MESSAGE_NOT_ALLOWED).
"""

import socket
import threading
import time
import pytest

from common.message_types import MessageType
from server.server_core import ServerCore
from client.client_core import ClientCore


def get_free_port() -> int:
    """Lấy cổng mạng ngẫu nhiên còn rảnh trên localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestMessageRoutingIntegration:
    """Bộ kiểm thử tích hợp cho hệ thống định tuyến tin nhắn thời gian thực."""

    def test_broadcast_message_reaches_all_clients(self):
        """Kiểm tra tin nhắn phát thanh (Broadcast) được gửi tới tất cả người dùng trong phòng."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        charlie = ClientCore(server_host="127.0.0.1", server_port=port)

        assert alice.connect() and alice.authenticate("Alice")[0]
        assert bob.connect() and bob.authenticate("Bob")[0]
        assert charlie.connect() and charlie.authenticate("Charlie")[0]

        bob_broadcasts = []
        charlie_broadcasts = []

        bob.register_callback(
            MessageType.CHAT_BROADCAST,
            lambda pkt: bob_broadcasts.append(pkt.to_json()),
        )
        charlie.register_callback(
            MessageType.CHAT_BROADCAST,
            lambda pkt: charlie_broadcasts.append(pkt.to_json()),
        )

        # Alice gửi tin nhắn phòng chung
        msg_text = "Chào toàn thể mọi người trong phòng!"
        assert alice.send_broadcast(msg_text) is True

        time.sleep(0.5)

        # Cả Bob và Charlie đều phải nhận được tin nhắn phòng chung từ Alice
        assert len(bob_broadcasts) >= 1
        assert bob_broadcasts[-1]["sender"] == "Alice"
        assert bob_broadcasts[-1]["content"] == msg_text

        assert len(charlie_broadcasts) >= 1
        assert charlie_broadcasts[-1]["sender"] == "Alice"
        assert charlie_broadcasts[-1]["content"] == msg_text

        alice.disconnect()
        bob.disconnect()
        charlie.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_direct_message_privacy(self):
        """
        Kiểm tra tính riêng tư của tin nhắn 1-1 (Unicast):
        Bob gửi cho Charlie -> Charlie nhận được, Bob nhận ACK, Alice HOÀN TOÀN KHÔNG nhận được.
        """
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        alice = ClientCore(server_host="127.0.0.1", server_port=port)
        bob = ClientCore(server_host="127.0.0.1", server_port=port)
        charlie = ClientCore(server_host="127.0.0.1", server_port=port)

        assert alice.connect() and alice.authenticate("Alice")[0]
        assert bob.connect() and bob.authenticate("Bob")[0]
        assert charlie.connect() and charlie.authenticate("Charlie")[0]

        alice_directs = []
        charlie_directs = []
        bob_acks = []

        alice.register_callback(
            MessageType.CHAT_DIRECT,
            lambda pkt: alice_directs.append(pkt.to_json()),
        )
        charlie.register_callback(
            MessageType.CHAT_DIRECT,
            lambda pkt: charlie_directs.append(pkt.to_json()),
        )
        bob.register_callback(
            MessageType.CHAT_ACK,
            lambda pkt: bob_acks.append(pkt.to_json()),
        )

        secret_text = "Đây là bí mật riêng tư chỉ dành cho Charlie!"
        assert bob.send_direct_message(recipient="Charlie", content=secret_text) is True

        time.sleep(0.5)

        # 1. Charlie nhận đúng tin nhắn riêng từ Bob
        assert len(charlie_directs) == 1
        assert charlie_directs[0]["sender"] == "Bob"
        assert charlie_directs[0]["recipient"] == "Charlie"
        assert charlie_directs[0]["content"] == secret_text

        # 2. Bob nhận được CHAT_ACK xác nhận tin nhắn đã tới tay Charlie
        assert len(bob_acks) == 1
        assert bob_acks[0]["status"] == "DELIVERED"
        assert bob_acks[0]["recipient"] == "Charlie"

        # 3. Alice KHÔNG HỀ nhận được bất kỳ tin nhắn riêng nào
        assert len(alice_directs) == 0

        alice.disconnect()
        bob.disconnect()
        charlie.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_direct_message_recipient_not_found(self):
        """Gửi tin nhắn riêng tới người dùng không online: Server phản hồi ERROR_NOTICE."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        client = ClientCore(server_host="127.0.0.1", server_port=port)
        assert client.connect() and client.authenticate("SenderUser")[0]

        client_errors = []
        client.register_callback(
            MessageType.ERROR_NOTICE,
            lambda pkt: client_errors.append(pkt.to_json()),
        )

        # Gửi tới "GhostUser" không tồn tại
        client.send_direct_message(recipient="GhostUser", content="Alo có đó không?")

        time.sleep(0.5)

        assert len(client_errors) == 1
        assert client_errors[0]["code"] == "USER_NOT_FOUND"
        assert "GhostUser" in client_errors[0]["message"]

        client.disconnect()
        server.stop()
        sthread.join(timeout=2.0)

    def test_direct_message_to_self_prevented(self):
        """Người dùng cố tình gửi tin nhắn riêng cho chính mình: Server phản hồi lỗi."""
        port = get_free_port()
        server = ServerCore(host="127.0.0.1", port=port)
        sthread = threading.Thread(target=server.serve_forever, daemon=True)
        sthread.start()
        time.sleep(0.3)

        client = ClientCore(server_host="127.0.0.1", server_port=port)
        assert client.connect() and client.authenticate("AliceSelf")[0]

        client_errors = []
        client.register_callback(
            MessageType.ERROR_NOTICE,
            lambda pkt: client_errors.append(pkt.to_json()),
        )

        # Alice tự gửi cho "aliceself"
        client.send_direct_message(recipient="aliceself", content="Tự nói chuyện một mình")

        time.sleep(0.5)

        assert len(client_errors) == 1
        assert client_errors[0]["code"] == "SELF_MESSAGE_NOT_ALLOWED"

        client.disconnect()
        server.stop()
        sthread.join(timeout=2.0)
