import socket
import struct
import threading
import time
import uuid

from cryptography.fernet import InvalidToken

from common.crypto_utils import get_shared_app_key
from common.message_types import MessageType
from common.protocol import (
    FLAG_ENCRYPTED,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    Packet,
    ProtocolError,
    create_packet,
)


def decode_datagram(data, key):
    if len(data) < HEADER_SIZE or len(data) > 4096:
        raise ValueError("Invalid discovery datagram size.")
    magic, version, kind, flags, reserved, length = struct.unpack(
        HEADER_FORMAT, data[:HEADER_SIZE]
    )
    if (
        magic != MAGIC_BYTES
        or version != PROTOCOL_VERSION
        or flags != FLAG_ENCRYPTED
        or reserved
        or length != len(data) - HEADER_SIZE
    ):
        raise ValueError("Invalid discovery frame.")
    return Packet(kind, data[HEADER_SIZE:], flags, version).get_decrypted_packet(key)


class DiscoveryResponder:
    def __init__(self, host, port, server_id, key):
        self.key = key
        self.port = port
        self.server_id = server_id
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((host, port))
            self.sock.settimeout(0.2)
        except OSError:
            self.sock.close()
            raise
        self.stopped = threading.Event()
        self.thread = threading.Thread(
            target=self.run, name="UDPDiscovery", daemon=True
        )
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                data, address = self.sock.recvfrom(4097)
                packet = decode_datagram(data, self.key)
                request = packet.to_json()
                if packet.msg_type != MessageType.DISCOVERY_REQ or not isinstance(
                    request, dict
                ):
                    continue
                nonce = request.get("nonce")
                if not isinstance(nonce, str) or len(nonce) != 32:
                    continue
                response = {
                    "nonce": nonce,
                    "server_id": self.server_id,
                    "port": self.port,
                }
                self.sock.sendto(
                    create_packet(
                        MessageType.DISCOVERY_RESP, response, encrypt_key=self.key
                    ),
                    address,
                )
            except socket.timeout:
                continue
            except (ValueError, ProtocolError, InvalidToken, UnicodeError):
                continue
            except OSError:
                break

    def close(self):
        self.stopped.set()
        self.sock.close()
        if threading.current_thread() is not self.thread:
            self.thread.join(timeout=0.5)


def discover_servers(port=9000, timeout=1.0, targets=("255.255.255.255", "127.0.0.1")):
    key = get_shared_app_key()
    nonce = uuid.uuid4().hex
    request = create_packet(
        MessageType.DISCOVERY_REQ, {"nonce": nonce}, encrypt_key=key
    )
    results = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for host in targets:
            try:
                sock.sendto(request, (host, port))
            except OSError:
                continue
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                data, address = sock.recvfrom(4097)
                packet = decode_datagram(data, key)
                response = packet.to_json()
                if (
                    packet.msg_type == MessageType.DISCOVERY_RESP
                    and isinstance(response, dict)
                    and response.get("nonce") == nonce
                    and type(response.get("port")) is int
                    and 1 <= response["port"] <= 65535
                ):
                    results[(address[0], response["port"])] = dict(
                        response, ip=address[0]
                    )
            except socket.timeout:
                break
            except (ValueError, ProtocolError, InvalidToken, UnicodeError):
                continue
    return list(results.values())
