# Distributed Client-Server Collaboration Application

Ứng dụng Python dùng socket TCP/UDP trực tiếp: server quản lý phiên và chat; file truyền P2P với khóa phiên X25519. Có GUI Tkinter và CLI.

**Protocol v2 không tương thích wire với v1: cập nhật cả server và tất cả client.**

## Cài đặt và cấu hình khóa

Python 3.10+. Linux chạy GUI cần python3-tk. PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:COLLAB_AES_KEY = '<khóa vừa sinh>'
```

Bắt buộc đặt **COLLAB_AES_KEY riêng**, giống nhau trong từng terminal server/client. Chia sẻ key riêng cho nhóm, không commit. Không còn fallback sang secret công khai trong source. Có thể dùng Fernet key hoặc passphrase riêng. Linux/macOS dùng `.venv/bin/python` và `export COLLAB_AES_KEY='<khóa>'`.

## Chạy server/client

```powershell
.\.venv\Scripts\python.exe run_server.py --host 0.0.0.0 --port 9000
.\.venv\Scripts\python.exe run_gui.py
.\.venv\Scripts\python.exe run_client.py --host 127.0.0.1 --port 9000 --username Alice
.\.venv\Scripts\python.exe run_client.py --discover --port 9000 --username Bob
```

Mỗi lệnh ứng dụng chạy trong một terminal riêng đã đặt key. GUI nhập IP, port và username 3–20 ký tự chữ ASCII/số/`_`/`-`; double-click người online để mở tab riêng. Chọn recipient rồi gửi file. Cửa sổ upload/download có nút hủy transfer.

`--discover` gửi UDP broadcast và loopback probe được bảo vệ bằng key phòng. Chỉ tự chọn khi có đúng một server trả lời; nếu không, dùng `--host`. Cố định cổng nhận P2P bằng `--p2p-port 50001` khi cần cấu hình firewall.

| Lệnh CLI | Chức năng |
|---|---|
| Văn bản thường | Chat chung |
| `@Bob nội dung`, `/msg Bob nội dung` | Chat riêng |
| `/file Bob đường_dẫn`, `/sendfile Bob đường_dẫn` | Gửi file P2P |
| `/users`, `/who` | Danh sách online |
| `/ping` | TCP heartbeat thủ công |
| `/quit`, `/exit` | Đăng xuất và đóng socket |

LAN: dùng IP LAN thật của server, không dùng loopback của máy khác. Firewall cần cho TCP cổng server, UDP cùng cổng cho discovery và TCP P2P trên máy nhận. P2P bị chặn sẽ báo lỗi, không relay file qua server.

## Bảo đảm và giới hạn

- Header 16 byte `!2sBHBHQ`. Payload mã hóa xác thực bản sao version/type/flags, ngăn đổi DM thành broadcast bằng header.
- Tracker ký ticket ngắn hạn gắn tên, session và khóa định danh Ed25519 của hai peer. Peer ký transcript chứa khóa X25519; không tin tên tự khai hoặc ACK plain. Offer/ACK phải đúng file_id.
- File chia 32 KiB, ghi staging tạo độc quyền, kiểm size/SHA-256 rồi commit tên mới không ghi đè, kể cả nhiều process. Filesystem phải hỗ trợ hard link; nếu không, transfer báo lỗi an toàn. Thư mục mặc định: storage/client_downloads.
- Mỗi file/tổng file đang nhận tối đa 2 GiB mỗi client; tối đa 8 worker nhận và 16 socket P2P được theo dõi. Chưa có resume.
- Server có queue gửi giới hạn và deadline gửi; recipient quá chậm có thể bị đóng. Broadcast xếp cùng thứ tự cho recipient được chấp nhận. CHAT_ACK xác nhận đã nhận định tuyến vào queue, không phải read receipt. FILE_ACK là xác nhận của peer hợp lệ về hash/commit, không chứng minh giữ file lâu dài.
- Username là danh tính của phiên online, chưa có tài khoản mật khẩu lâu dài. Key phòng là ranh giới tin cậy nhóm; không chống thành viên biết key chủ động giả central server trên mạng. Khóa phiên được bỏ tham chiếu, không cam kết zeroization RAM Python.

## Kiểm thử

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe tests/stress_test.py --clients 20 --duration 5
```

Fixture pytest cấp key riêng cho test. Stress độc lập cần COLLAB_AES_KEY như ứng dụng. GUI test cần Tcl/Tk/display; Linux CI dùng Xvfb. CI chạy trên main, branch proposal/** và PR vào main; phải xem kết quả thực trên GitHub trước khi khẳng định nhiều OS đã đạt.

Xem [protocol](docs/protocol_specs.md), [báo cáo kỹ thuật](docs/technical_report.md), [đối chiếu sửa lỗi](docs/review_fixes.md). Nguồn LaTeX báo cáo v2: docs/main.tex.
