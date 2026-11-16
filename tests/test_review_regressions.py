import hashlib
import multiprocessing
import socket
import struct
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from client.client_core import ClientCore
from client.file_transfer import IncomingFileTransfer
from client.gui.app import CollabChatApp
from common.crypto_utils import get_shared_app_key, generate_ephemeral_x25519_keypair
from common.discovery import discover_servers
from common.message_types import MessageType as M
from common.peer_auth import public_key_text, sign, check_ticket
from common.protocol import (
    PROTOCOL_VERSION,
    ProtocolError,
    ConnectionClosedError,
    create_packet,
    recv_packet,
    recv_secure_packet,
)
from server.server_core import ServerCore


def wait_for(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


@pytest.fixture
def room():
    server = ServerCore("127.0.0.1", 0)
    server.start()
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    clients = []

    def connect(name, **kwargs):
        client = ClientCore("127.0.0.1", server.port, name)
        clients.append(client)
        assert client.connect(timeout=2, **kwargs)
        assert client.authenticate(name, timeout=2)[0]
        return client

    try:
        yield server, connect
    finally:
        for client in clients:
            client.disconnect()
        server.stop()
        worker.join(timeout=1)


@pytest.mark.parametrize("kind", [M.CHAT_BROADCAST, M.AUTH_REQ, M.FILE_OFFER_REQ])
def test_encrypted_header_context_rejects_type_changes(kind):
    key = get_shared_app_key()
    original = create_packet(
        M.CHAT_DIRECT, {"recipient": "Bob", "content": "secret"}, encrypt_key=key
    )
    altered = original[:3] + struct.pack("!H", kind) + original[5:]
    a, b = socket.socketpair()
    try:
        a.sendall(altered)
        with pytest.raises(ProtocolError):
            recv_packet(b, decrypt_key=key)
    finally:
        a.close()
        b.close()


def test_modified_dm_cannot_be_broadcast(room):
    server, connect = room
    alice = connect("Alice", start_p2p=False)
    connect("Bob", start_p2p=False)
    charlie = connect("Charlie", start_p2p=False)
    received = []
    charlie.register_callback(
        M.CHAT_BROADCAST, lambda packet: received.append(packet.to_json())
    )
    frame = create_packet(
        M.CHAT_DIRECT,
        {"recipient": "Bob", "content": "private"},
        encrypt_key=alice.crypto_key,
    )
    frame = frame[:3] + struct.pack("!H", M.CHAT_BROADCAST) + frame[5:]
    alice.sock.sendall(frame)
    assert wait_for(lambda: not server.session_mgr.is_online("Alice"))
    assert received == []


def test_peer_without_tracker_session_cannot_connect(room):
    _, connect = room
    bob = connect("Bob")
    guest = ClientCore(client_name="Alice")
    peer, key, reason = guest._connect_p2p_peer("Bob", "127.0.0.1", bob.p2p_port, 1)
    assert peer is None and key is None
    assert "authenticated" in reason


def test_member_cannot_claim_another_senders_ticket(room):
    _, connect = room
    alice, bob, mallory = connect("Alice"), connect("Bob"), connect("Mallory")
    assert alice.lookup_peer("Bob")[0]
    ticket = alice._lookup_local.ticket
    _, public = generate_ephemeral_x25519_keypair()
    hello = {
        "sender": "Alice",
        "protocol_version": PROTOCOL_VERSION,
        "ticket": ticket,
        "x25519_pub": public,
    }
    hello["proof"] = sign(mallory._identity_key, hello)
    with socket.create_connection(("127.0.0.1", bob.p2p_port), timeout=2) as sock:
        sock.sendall(create_packet(M.PEER_HELLO, hello, encrypt_key=mallory.crypto_key))
        with pytest.raises(ConnectionClosedError):
            recv_packet(sock)
    assert alice.is_authenticated and bob.is_authenticated


def test_ticket_is_bound_to_recipient_session_and_expires(room):
    server, connect = room
    alice, bob = connect("Alice"), connect("Bob")
    assert alice.lookup_peer("Bob")[0]
    ticket = alice._lookup_local.ticket
    bob.session_id = "another-session"
    _, public = generate_ephemeral_x25519_keypair()
    hello = {
        "sender": "Alice",
        "protocol_version": PROTOCOL_VERSION,
        "ticket": ticket,
        "x25519_pub": public,
    }
    hello["proof"] = sign(alice._identity_key, hello)
    with socket.create_connection(("127.0.0.1", bob.p2p_port), timeout=2) as sock:
        sock.sendall(create_packet(M.PEER_HELLO, hello, encrypt_key=alice.crypto_key))
        with pytest.raises(ConnectionClosedError):
            recv_packet(sock)
    claims = dict(ticket["claims"], expires=time.time() - 1)
    expired = {"claims": claims, "signature": sign(server._ticket_key, claims)}
    with pytest.raises(ValueError, match="Expired"):
        check_ticket(expired, public_key_text(server._ticket_key))


def test_tracker_ticket_cannot_be_replayed(room):
    _, connect = room
    alice, bob = connect("Alice"), connect("Bob")
    assert alice.lookup_peer("Bob")[0]
    ticket = alice._lookup_local.ticket
    peer, key, error = alice._connect_p2p_peer(
        "Bob", "127.0.0.1", bob.p2p_port, 1, ticket=ticket
    )
    assert peer is not None, error
    peer.close()
    repeated, _, _ = alice._connect_p2p_peer(
        "Bob", "127.0.0.1", bob.p2p_port, 1, ticket=ticket
    )
    assert repeated is None


def test_plaintext_offer_rejected_after_authenticated_handshake(room, tmp_path):
    _, connect = room
    alice, bob = connect("Alice"), connect("Bob")
    bob.download_dir = str(tmp_path)
    sock, key, error = alice._connect_p2p_peer("Bob", "127.0.0.1", bob.p2p_port, 1)
    assert sock is not None, error
    try:
        sock.sendall(create_packet(M.FILE_OFFER_REQ, {"file_id": "plain"}))
        with pytest.raises(ConnectionClosedError):
            recv_packet(sock)
        assert wait_for(lambda: not bob.incoming_files)
        assert list(tmp_path.iterdir()) == []
    finally:
        sock.close()


def test_fake_receiver_without_room_key_is_not_accepted(room):
    _, connect = room
    alice = connect("Alice")
    connect("Bob")
    assert alice.lookup_peer("Bob")[0]
    ticket = alice._lookup_local.ticket
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    endpoint = listener.getsockname()

    def fake():
        with listener:
            peer, _ = listener.accept()
            with peer:
                recv_packet(peer)
                _, public = generate_ephemeral_x25519_keypair()
                peer.sendall(
                    create_packet(
                        M.PEER_HELLO_ACK,
                        {
                            "status": "OK",
                            "protocol_version": PROTOCOL_VERSION,
                            "username": "Bob",
                            "x25519_pub": public,
                        },
                    )
                )

    thread = threading.Thread(target=fake, daemon=True)
    thread.start()
    sock, key, reason = alice._connect_p2p_peer("Bob", *endpoint, 1, ticket=ticket)
    thread.join(timeout=2)
    assert sock is None and key is None


@pytest.mark.parametrize("wrong_step", ["offer_id", "ack_id", "plain_ack"])
def test_file_responses_require_encryption_and_current_file_id(
    room, tmp_path, monkeypatch, wrong_step
):
    _, connect = room
    alice = connect("Alice")
    connect("Bob")
    peer, sender = socket.socketpair()
    key = get_shared_app_key("One-transfer-only-key")
    errors = []

    def fake():
        try:
            with peer:
                offer = recv_secure_packet(peer, key).to_json()
                peer.sendall(
                    create_packet(
                        M.FILE_OFFER_RESP,
                        {
                            "status": "ACCEPTED",
                            "file_id": "wrong"
                            if wrong_step == "offer_id"
                            else offer["file_id"],
                        },
                        encrypt_key=key,
                    )
                )
                if wrong_step != "offer_id":
                    recv_secure_packet(peer, key)
                    peer.sendall(
                        create_packet(
                            M.FILE_ACK,
                            {
                                "status": "SUCCESS",
                                "file_id": "wrong"
                                if wrong_step == "ack_id"
                                else offer["file_id"],
                            },
                            encrypt_key=None if wrong_step == "plain_ack" else key,
                        )
                    )
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=fake, daemon=True)
    worker.start()
    monkeypatch.setattr(
        alice, "_connect_p2p_peer", lambda *args, **kwargs: (sender, key, None)
    )
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    success, reason = alice.send_file("Bob", str(source), timeout=1)
    worker.join(timeout=2)
    assert not success
    assert not errors


def test_same_recipient_lookups_and_files_can_run_concurrently(room, tmp_path):
    _, connect = room
    alice, bob = connect("Alice"), connect("Bob")
    bob.download_dir = str(tmp_path / "received")
    results = []
    sources = []
    for i in range(4):
        source = tmp_path / f"file-{i}.bin"
        source.write_bytes(bytes([i]) * 50000)
        sources.append(source)
    barrier = threading.Barrier(4)

    def send(source):
        barrier.wait(timeout=2)
        results.append(alice.send_file("Bob", str(source), timeout=3))

    workers = [threading.Thread(target=send, args=(source,)) for source in sources]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=6)
    assert len(results) == 4 and all(ok for ok, _ in results), results
    for source in sources:
        assert (tmp_path / "received" / source.name).read_bytes() == source.read_bytes()


def test_staging_file_does_not_replace_a_preexisting_part_file(tmp_path):
    existing = tmp_path / "report.txt.known.part"
    existing.write_bytes(b"original")
    data = b"new"
    transfer = IncomingFileTransfer(
        "known",
        "Alice",
        "report.txt",
        len(data),
        1,
        hashlib.sha256(data).hexdigest(),
        str(tmp_path / "report.txt"),
    )
    transfer.add_chunk(0, data)
    assert transfer.assemble_and_verify()[0]
    assert existing.read_bytes() == b"original"
    assert (tmp_path / "report.txt").read_bytes() == data


def _commit_in_process(directory, content, barrier, results):
    from pathlib import Path

    path = Path(directory) / "shared.txt"
    transfer = IncomingFileTransfer(
        content.decode(),
        "Sender",
        "shared.txt",
        len(content),
        1,
        hashlib.sha256(content).hexdigest(),
        str(path),
    )
    transfer.add_chunk(0, content)
    barrier.wait(timeout=5)
    results.put(transfer.assemble_and_verify()[0])


def test_two_processes_commit_without_overwriting(tmp_path):
    context = multiprocessing.get_context("spawn")
    barrier, results = context.Barrier(2), context.Queue()
    workers = [
        context.Process(
            target=_commit_in_process, args=(str(tmp_path), content, barrier, results)
        )
        for content in (b"first", b"second")
    ]
    for worker in workers:
        worker.start()
    try:
        for worker in workers:
            worker.join(timeout=10)
            assert worker.exitcode == 0
        assert results.get(timeout=1) and results.get(timeout=1)
        assert {p.read_bytes() for p in tmp_path.glob("*.txt")} == {b"first", b"second"}
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=1)


def test_disconnect_closes_idle_p2p_sockets_and_workers(room):
    _, connect = room
    bob = connect("Bob")
    peers = [
        socket.create_connection(("127.0.0.1", bob.p2p_port), timeout=1)
        for _ in range(3)
    ]
    assert wait_for(lambda: len(bob._p2p_worker_threads) == 3)
    workers = list(bob._p2p_worker_threads)
    try:
        bob.disconnect()
        assert not any(worker.is_alive() for worker in workers)
        assert not bob._p2p_sockets
    finally:
        for peer in peers:
            peer.close()


def test_p2p_worker_count_is_bounded(room):
    _, connect = room
    bob = connect("Bob")
    peers = [
        socket.create_connection(("127.0.0.1", bob.p2p_port), timeout=2)
        for _ in range(12)
    ]
    try:
        assert wait_for(lambda: len(bob._p2p_worker_threads) >= 8)
        assert len(bob._p2p_worker_threads) == 8
    finally:
        for peer in peers:
            peer.close()


def test_udp_discovery_on_loopback(room):
    server, _ = room
    servers = discover_servers(port=server.port, timeout=0.3, targets=("127.0.0.1",))
    assert [(item["ip"], item["port"]) for item in servers] == [
        ("127.0.0.1", server.port)
    ]


def test_slow_recipient_does_not_change_broadcast_order(room):
    server, connect = room
    alice, bob = connect("Alice", start_p2p=False), connect("Bob", start_p2p=False)
    seen_alice, seen_bob = [], []
    alice.register_callback(
        M.CHAT_BROADCAST, lambda packet: seen_alice.append(packet.to_json()["content"])
    )
    bob.register_callback(
        M.CHAT_BROADCAST, lambda packet: seen_bob.append(packet.to_json()["content"])
    )
    handler = server.session_mgr.get_session("Bob").handler
    real = handler.send_packet
    paused, release = threading.Event(), threading.Event()

    def delayed(kind, payload=b"", flags=0):
        if kind == M.CHAT_BROADCAST and payload["content"] == "first":
            paused.set()
            assert release.wait(timeout=2)
        return real(kind, payload, flags)

    handler.send_packet = delayed
    alice.send_broadcast("first")
    assert paused.wait(timeout=2)
    bob.send_broadcast("second")
    release.set()
    assert wait_for(lambda: len(seen_alice) == 2 and len(seen_bob) == 2)
    assert seen_alice == seen_bob == ["first", "second"]


def test_download_cancel_callback_and_stale_gui_event(monkeypatch):
    factory = MagicMock()
    monkeypatch.setattr("client.gui.app.FileProgressDialog", factory)
    app = SimpleNamespace(
        chat_view=MagicMock(),
        client=MagicMock(),
        file_dialogs={},
        download_dialogs_by_key={},
        _cancel_download=MagicMock(),
    )
    CollabChatApp._dispatch_gui_event(
        app, "incoming_file_start", ("id", "Alice", "x.bin", 10, 1)
    )
    factory.call_args.kwargs["on_cancel"]()
    app._cancel_download.assert_called_once_with("id")
    app._session_generation = 2
    assert not CollabChatApp._post_event(app, "disconnected", "old session", 1)


def test_disconnect_handles_concurrent_receiver_cleanup():
    client = ClientCore()
    client.is_connected = True

    class FakeSocket:
        def sendall(self, data):
            client._reset_session_state()

        def shutdown(self, how):
            pass

        def close(self):
            pass

    client.sock = FakeSocket()
    client.disconnect()
    assert client.sock is None and not client.is_connected


def test_download_cancel_aborts_socket_and_removes_staging(room, tmp_path):
    _, connect = room
    alice, bob = connect("Alice"), connect("Bob")
    bob.download_dir = str(tmp_path / "received")
    source = tmp_path / "cancel.bin"
    source.write_bytes(b"x" * (8 * 1024 * 1024))
    bob.on_file_progress = lambda file_id, *args: bob.cancel_incoming_file(file_id)
    success, _ = alice.send_file("Bob", str(source), timeout=2)
    assert not success
    assert wait_for(lambda: not bob.incoming_files)
    assert list((tmp_path / "received").iterdir()) == []


def test_upload_cancel_interrupts_waiting_for_offer(room, tmp_path, monkeypatch):
    _, connect = room
    alice, bob = connect("Alice"), connect("Bob")
    bob.download_dir = str(tmp_path / "received")
    cancel = threading.Event()

    def delayed_offer(*args):
        cancel.set()
        time.sleep(0.2)
        return None

    monkeypatch.setattr(bob, "_prepare_incoming_p2p_transfer", delayed_offer)
    source = tmp_path / "x.bin"
    source.write_bytes(b"data")
    started = time.monotonic()
    success, _ = alice.send_file("Bob", str(source), timeout=2, cancel_event=cancel)
    assert not success
    assert time.monotonic() - started < 1.5


def test_fifty_mib_p2p_roundtrip(room, tmp_path):
    _, connect = room
    alice, bob = connect("Alice"), connect("Bob")
    bob.download_dir = str(tmp_path / "received")
    source = tmp_path / "large.bin"
    with source.open("wb") as stream:
        for _ in range(50):
            stream.write(bytes(range(256)) * 4096)
    success, reason = alice.send_file("Bob", str(source), timeout=5)
    assert success, reason
    target = tmp_path / "received" / source.name
    from client.file_transfer import calculate_file_hash

    assert target.stat().st_size == 50 * 1024 * 1024
    assert calculate_file_hash(source) == calculate_file_hash(target)
    assert not list(target.parent.glob("*.part"))


def test_client_detects_missing_pong(room):
    _, connect = room
    alice = connect("Alice")
    alice._last_pong = time.monotonic() - 20
    assert wait_for(lambda: not alice.is_connected)
    assert alice.sock is None and not alice.is_authenticated


def test_slow_writer_queue_is_bounded_and_other_clients_survive(room):
    server, connect = room
    slow, fast = connect("Slow"), connect("Fast")
    handler = server.session_mgr.get_session("Slow").handler
    underlying = handler.client_sock
    blocked, release = threading.Event(), threading.Event()

    class SlowSocket:
        def sendall(self, data):
            blocked.set()
            release.wait(timeout=4)
            raise OSError("closed slow receiver")

        def shutdown(self, how):
            release.set()
            return underlying.shutdown(how)

        def close(self):
            return underlying.close()

        def __getattr__(self, name):
            return getattr(underlying, name)

    handler.client_sock = SlowSocket()
    handler.send_packet(M.CHAT_BROADCAST, {"content": "block"})
    assert blocked.wait(timeout=1)
    for _ in range(160):
        handler.send_packet(M.CHAT_BROADCAST, {"content": "queued"})
    assert wait_for(lambda: not server.session_mgr.is_online("Slow"))
    assert handler._outgoing.qsize() <= 128
    assert fast.request_user_list(timeout=1) == ["Fast"]


def test_parallel_logins_converge_without_manual_presence_refresh(room):
    _, connect = room
    clients = []
    errors = []

    def login(index):
        try:
            clients.append(connect(f"Concurrent{index}"))
        except Exception as exc:
            errors.append(exc)

    workers = [threading.Thread(target=login, args=(i,)) for i in range(6)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=4)
    assert not errors and len(clients) == 6
    expected = {client.username for client in clients}
    assert wait_for(
        lambda: all(set(client.online_users) == expected for client in clients)
    )
