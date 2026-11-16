# Distributed Client-Server Collaboration Application

Hướng dẫn cài đặt môi trường và khởi chạy ứng dụng cộng tác phân tán (Chat phòng chung, Chat riêng 1-1 và Truyền file P2P trực tiếp) qua TCP Socket.

---

## 1. Yêu cầu & Cài đặt Môi trường

### Yêu cầu hệ thống
- **Python 3.10 trở lên** (khuyên dùng Python 3.10 – 3.12) trên Windows, macOS hoặc Linux.
- Nếu chạy giao diện đồ họa (**GUI**) trên **Linux/Ubuntu**, cần cài sẵn Tkinter:
  ```bash
  sudo apt-get install -y python3-tk libtk8.6
  ```

### Cài đặt thư viện trong môi trường ảo (`venv`)
Mở terminal tại thư mục gốc của dự án (sau khi giải nén hoặc clone) và chạy:

```bash
# 1. Tạo môi trường ảo
python -m venv venv

# 2. Kích hoạt môi trường ảo
# - Windows (PowerShell):
.\venv\Scripts\activate
# - Windows (CMD):
venv\Scripts\activate.bat
# - Linux / macOS:
source venv/bin/activate

# 3. Cài đặt thư viện phụ thuộc (cryptography)
pip install -r requirements.txt
```

---

## 2. Khởi chạy Server

```bash
# Chạy Server mặc định tại 0.0.0.0:9000
python run_server.py

# Hoặc chỉ định rõ IP, cổng và tên Server
python run_server.py --host 0.0.0.0 --port 9000 --server-id CollabServer-Alpha
```

> **Lưu ý về mã hóa tự động:** Hệ thống tự động mã hóa lưu lượng bằng khóa chung mặc định (hoặc qua biến môi trường `COLLAB_AES_KEY`). Nếu tự đặt `COLLAB_AES_KEY`, hãy đặt giá trị giống nhau ở cả Server và các Client:
> - **PowerShell:** `$env:COLLAB_AES_KEY="MyTeamSecretKey"` rồi chạy `python run_server.py`
> - **Linux / macOS:** `COLLAB_AES_KEY="MyTeamSecretKey" python run_server.py`

---

## 3. Khởi chạy Client (GUI & CLI)

### 3.1. Chạy Client bằng Giao diện Đồ họa (GUI Tkinter)
Mỗi người dùng mở một terminal mới (đã kích hoạt `venv`) và chạy:

```bash
python run_gui.py
```

**Thao tác nhanh trên GUI:**
1. Nhập **Địa chỉ Server IP** (`127.0.0.1` nếu chạy trên cùng máy, hoặc IP LAN của máy Server như `192.168.1.x`).
2. Nhập **Cổng kết nối (Port)** (`9000`) và **Tên người dùng (Username)** (`3–20` ký tự gồm chữ, số, `_` hoặc `-`), sau đó bấm **🚀 Kết nối & Tham gia phòng**.
3. **Chat phòng chung:** Gõ và nhấn Enter ở tab phòng chung.
4. **Chat riêng 1-1:** Nhấp đúp (double-click) vào tên người dùng ở danh sách bên trái để mở tab chat riêng.
5. **Gửi file P2P trực tiếp:** Chọn người nhận trong danh sách Online (hoặc mở sẵn tab chat riêng của người đó), rồi bấm nút **📎 Gửi File** để chọn tệp cần gửi (file nhận về được lưu tại thư mục `storage/client_downloads/`).

### 3.2. Chạy Client bằng Dòng lệnh (CLI Terminal)
Mở terminal mới (đã kích hoạt `venv`) và chạy:

```bash
# Chạy CLI với các tham số mặc định (127.0.0.1:9000, hỏi username khi kết nối)
python run_client.py

# Hoặc truyền sẵn thông tin kết nối và Username
python run_client.py --host 127.0.0.1 --port 9000 --username Bob --p2p-port 0
```

**Các lệnh sử dụng trong CLI:**

| Lệnh / Cú pháp | Ví dụ | Chức năng |
| :--- | :--- | :--- |
| `<nội dung>` | `Xin chào mọi người` | Gửi tin nhắn tới phòng chung |
| `@<user> <nội dung>` hoặc `/msg <user> <nội dung>` | `@Alice Mình gửi file nhé` | Gửi tin nhắn riêng 1-1 tới một người dùng |
| `/file <user> <đường_dẫn>` hoặc `/sendfile <user> <đường_dẫn>` | `/file Alice ./report.pdf` | Gửi file trực tiếp P2P (lưu ở `storage/client_downloads/` bên nhận) |
| `/users` hoặc `/who` | `/users` | Xem danh sách người dùng đang online |
| `/ping` | `/ping` | Gửi gói kiểm tra nhịp tim (`HEARTBEAT_PING`) lên Server |
| `/quit` hoặc `/exit` | `/quit` | Đăng xuất và đóng kết nối an toàn |

---

## 4. Lưu ý khi chạy trên nhiều máy qua mạng LAN

- **Địa chỉ Server:** Các máy Client phải kết nối tới **IP LAN thực tế** của máy chạy Server (ví dụ `--host 192.168.1.15`), không dùng `127.0.0.1`.
- **Firewall (Tường lửa):** Mở inbound TCP cho **cổng Server** (`9000`) trên máy Server và **cổng P2P** trên các máy Client (có thể cố định cổng P2P khi chạy CLI bằng `--p2p-port 50001` để dễ mở rule Firewall).
- **Thư mục nhận file:** Mọi file nhận qua P2P sau khi kiểm tra toàn vẹn `SHA-256` sẽ được tự động lưu vào `storage/client_downloads/` (tự động đổi tên nếu trùng, không ghi đè file cũ).
