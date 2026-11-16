# Review fixes proposed from 991a777

Branch: proposal/review-security-resilience-fixes. The branch starts from upstream main commit 991a777 and implements the findings from the submitted-source review. They do not alter the external submission ZIP/PDF or the earlier review reports.

## Compatibility and setup

- Protocol version is 2. Upgrade server and all clients together; the encrypted payload now authenticates version/type/flags.
- COLLAB_AES_KEY must be set privately on every process. The public default secret is removed. CLI configuration errors use argparse feedback; GUI reports the configuration failure on login.
- UDP discovery uses the server's TCP port number over UDP; allow that traffic in addition to TCP when using --discover.
- Final file commit requires filesystem hard-link support. Unsupported filesystems fail safely instead of using an overwrite-prone fallback.

## Mapping to report1b

| Review item | Implemented behavior |
|---|---|
| N1: mutable routing header | Fernet plaintext includes authenticated version/type/flags; header mismatch is rejected before routing. |
| N2/N4: fake/plain peer responses | Secure receive paths require encrypted P2P packets; handshake validates identity/version/ticket, offer/final responses require current file_id. |
| N3: unauthenticated/self-claimed peer | Ed25519 identity keys are registered per session; tracker-signed 30-second tickets bind both peers/sessions/keys; signed X25519 transcripts prove possession and reject replay. |
| N5: predictable staging and overwrite races | Exclusive unpredictable temporary files, synchronized cleanup and no-overwrite hard-link final commit, tested across two processes. |
| N6: same-target request races | Unique request_id echoed by every lookup response; separate Event/result and per-thread ticket state. |
| N7: untracked worker sockets | Bounded worker/socket registries, socket shutdown on disconnect/cancel, bounded join budget and packet-read deadlines. |
| N8: disconnect race | Preserve the upstream captured-socket fix; centralize detachment/reset and wake pending waiters; ignore old-connection packets after reconnect. |
| N9: download cancel | Download dialogs cancel by transfer ID; upload cancellation reaches an active transfer socket and can interrupt ACK/offer waits. |
| N10: broadcast order | Serialize enqueue order across recipients, use bounded per-handler writer queues and close slow recipients on overflow/send timeout. |
| Presence/session GUI races | Serialize auth response/presence snapshots; tag GUI events by generation; capture the upload's original client; key file completion by file_id. |
| Missing UDP discovery | Encrypted nonce-bound UDP discovery responder/client and CLI --discover; direct host selection remains available. |
| RAM/resource bounds | Core queue remains opt-in/bounded; GUI event work/queue and visible history are bounded; P2P workers, connections, sizes and control frames have caps. |
| Misleading documentation | README, protocol specification and technical report/LaTeX describe v2 and actual trust/receipt/key-lifetime limits. |

## Verification

Final local suite: **104 passed in 39.59 seconds** on 17 November 2026, with unhandled thread exceptions treated as failures. A separate 20-client, five-second traffic run completed with exit code 0. Tests treat unhandled thread exceptions as failures. The regression suite includes adversarial framing, authenticated P2P, forged ACKs, ticket replay/expiry/session substitution, simultaneous file sends, cross-process commits, cancellation, bounded workers/queues, missing PONG, UDP loopback discovery and simultaneous login convergence.

Environment: Windows 11 build 26200, Python 3.13.7, cryptography 50.0.2, pytest 9.2.0. Existing GUI tests use the available local Tcl/Tk runtime; Linux CI uses Xvfb. CI is configured for Windows/Linux/macOS Python 3.12 on main, proposal/** and PRs into main. Local validation does not claim that remote CI or real multi-machine LAN tests have completed.

Source checks include undefined-name linting, formatting of changed Python files, git diff whitespace validation and a tokenizer check that no newly added Python comments violate the requested rule. Existing valid comments remain; new explanatory comments were not added.

LaTeX source was synchronized to the v2 report. This machine has no LaTeX compiler, so PDF typesetting was not executed here. The external main-3.pdf remains the original submitted artifact and should not be presented as an updated v2 PDF.

## Trust and scope limits

Username login is an online-session registry, not a persistent account database. A private room key establishes group trust; it does not resist a holder actively impersonating the central server. Peer success ACKs report verified commit, not proof of future retention. CHAT_ACK reports routing/queue acceptance, not a read receipt. Python key reference cleanup is not secure memory zeroization. File resume, relay fallback and long-duration resource profiling are outside the implemented guarantees.

### Observed load output

```text
🚀 [Stress Test] Bắt đầu khởi tạo 20 Clients kết nối đồng thời tới 127.0.0.1:58233...
✅ [Stress Test] 20/20 Clients kết nối & đăng nhập thành công trong 0.10s!
   - Tổng số Clients hoạt động: 20/20
   - Thời gian test tải: 5.20s
   - Tổng số tin nhắn đã gửi: 606 messages (Broadcast: 400, Direct: 206 | 116.6 msgs/sec)
   - Tổng số lượt tin nhắn nhận: 8206/8206 deliveries (100.0%)
```

These are short localhost measurements, not maximum throughput or a soak-test guarantee. The suite also verifies a 50 MiB (1,600 chunk) P2P round trip and matching SHA-256.
