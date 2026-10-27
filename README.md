# Distributed Client-Server Collaboration Application

Dự án bài tập lớn môn **Network Application Development**.

Hệ thống cộng tác Client-Server phân tán được xây dựng từ đầu (from scratch) bằng **Raw Sockets** (TCP/UDP), hỗ trợ xác thực người dùng, định tuyến tin nhắn thời gian thực (phòng chung & riêng tư), truyền file tin cậy (chunking, SHA-256) và bảo mật dữ liệu bằng mã hóa tầng ứng dụng.

---

## 📖 Kế hoạch phát triển chi tiết (Roadmap)

Toàn bộ lộ trình xây dựng từng bước từ 0 đến 10 điểm (theo sát Rubric của giảng viên), kiến thức mạng cần nắm và bộ câu hỏi ôn tập vấn đáp bảo vệ đồ án đã được lập chi tiết tại:

👉 **[Xem kế hoạch chi tiết tại DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md)**

---

## 🛠️ Công nghệ sử dụng
- **Ngôn ngữ:** Python 3.10+
- **Mạng:** Raw Sockets (`socket` standard library - No HTTP/WebSocket libraries)
- **Đa luồng:** `threading`
- **Mã hóa:** `cryptography` (AES)
- **Giao diện:** Tkinter / CustomTkinter