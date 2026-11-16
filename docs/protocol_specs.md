# Application protocol v2

TCP carries server chat/control and direct P2P files. UDP discovery uses one encrypted frame per datagram. Upgrade both sides together; v1 frames are rejected.

## Header

Network byte order, `!2sBHBHQ`, exactly 16 bytes:

| Offset | Field | Bytes | Value |
|---|---|---:|---|
| 0–1 | Magic | 2 | CA |
| 2 | Version | 1 | 2 |
| 3–4 | Type | 2 | Registry below |
| 5 | Flags | 1 | 0x00 plain or 0x01 encrypted |
| 6–7 | Reserved | 2 | Zero |
| 8–15 | Wire payload length | 8 | Bytes following header |

Unknown flags/nonzero reserved fields are rejected; compression is not implemented. Generic frame cap is 50 MiB. Control/P2P paths use 64 KiB; central HELLO has a 64 KiB cap and 10-second total monotonic deadline. UDP datagrams are capped at 4096 bytes.

## Authenticated meaning

Encrypted plaintext is `struct.pack('!BHB', version, type, flags_including_encrypted) + application_payload`. After Fernet verification/decryption, the receiver compares this prefix with its external header and removes it before parsing JSON/binary. Reclassifying an encrypted DM as broadcast cannot reuse the original ciphertext.

`recv_secure_packet` requires encrypted framing when a key is configured. Supplying decrypt_key to generic recv_packet alone is not that enforcement; generic parsing is retained for wire-inspection tests.

## Registry

| Codes | Messages |
|---|---|
| 101/102/103 | HELLO_HANDSHAKE / HANDSHAKE_ACK / HANDSHAKE_REJECT |
| 104/105/106 | AUTH_REQ / AUTH_RESP_SUCCESS / AUTH_RESP_FAIL |
| 201/202/203 | USER_LIST_REQ / USER_LIST_RESP / USER_STATUS_BROADCAST |
| 204/205 | PEER_LOOKUP_REQ / PEER_LOOKUP_RESP |
| 301/302/303 | CHAT_BROADCAST / CHAT_DIRECT / CHAT_ACK |
| 401/402/403/404 | FILE_OFFER_REQ / FILE_OFFER_RESP / FILE_CHUNK / FILE_ACK |
| 405/406 | PEER_HELLO / PEER_HELLO_ACK |
| 501/502 | TCP HEARTBEAT_PING / HEARTBEAT_PONG |
| 503/504 | UDP DISCOVERY_REQ / DISCOVERY_RESP |
| 601/602 | DISCONNECT_NOTICE / ERROR_NOTICE |

The initial plain HELLO negotiates version/server identity/encryption mode/tracker verification key. Auth, user lists/presence, tracker lookups and chat/ACK use the configured room key. Minimal errors, heartbeat and disconnect remain control signals without file/chat contents. Normal entrypoints require a private room key; keyless mode is an explicit library setting.

## Sessions and request correlation

AUTH_REQ registers username, p2p_port and an Ed25519 identity_key. The tracker uses the observed TCP source IP; a claimed p2p_host does not override it. AUTH_RESP_SUCCESS returns username, session_id, online_users and peers. Names are unique case-insensitively while online.

PEER_LOOKUP_REQ includes a unique request_id; every response echoes it. Success returns endpoint and ticket. Separate request IDs prevent two lookups of the same username overwriting each other's waiter.

Ticket claims: id, sender, recipient, sender_session, recipient_session, sender_key, recipient_key, expires. The tracker signs canonical UTF-8 JSON (sorted keys, compact separators) with Ed25519. The signing private key is generated per server instance. Tickets expire after 30 seconds and are consumed once by the recipient.

## Direct P2P

1. Sender obtains a ticket for the current sessions.
2. Room-key encrypted PEER_HELLO contains sender, protocol_version, x25519_pub, ticket and proof. The sender signs the hello without proof using its registered identity private key.
3. Receiver verifies tracker signature, expiry, recipient/session/key, sender proof and replay cache. It derives a Fernet session key using X25519 and HKDF-SHA256.
4. Encrypted PEER_HELLO_ACK carries OK, receiver username, version, ephemeral key, ticket_id and proof. The receiver signs `{hello, reply_without_proof}`. Sender verifies expected identity and transcript.
5. Session-key encrypted FILE_OFFER_REQ contains file_id, sender, recipient, file_name, file_size, total_chunks and SHA-256. Offer responses and final ACK must be encrypted and match the file_id.
6. Each FILE_CHUNK plaintext contains four-byte metadata JSON length, metadata JSON and binary chunk. Metadata: file_id, chunk_index, total_chunks, chunk_size. Indices, chunk count/length and total bytes are validated. Empty files use one empty chunk.
7. Receiver streams to exclusively created staging, verifies size/chunks/hash, then commits a unique no-overwrite final filename. One encrypted FILE_ACK reports SUCCESS/FAILED. There is no ACK per chunk or resume protocol above TCP.

Shutdown/cancel closes the corresponding socket so blocked I/O wakes and staging is removed. Workers, sockets, incoming sizes and packet-read durations are bounded. Dropping key references is not a promise of secure RAM zeroization.

## UDP discovery

The request contains a fresh 32-character nonce. The encrypted response echoes nonce, server_id and TCP port. Client uses observed UDP source IP. Wrong key, type, size, version or nonce is rejected. Discovery selects an address under group room-key trust; it is not an external certificate authority.
