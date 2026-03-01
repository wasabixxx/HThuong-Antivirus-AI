# 📋 TODO — HThuong Antivirus AI

> Danh sách công việc cần hoàn thiện để dự án sẵn sàng demo trước hội đồng.
> Đánh dấu `[x]` khi hoàn thành.

---

## 🔴 Ưu tiên cao — Phải xong trước demo

### Backend (Python/FastAPI)

- [ ] **Thêm endpoint quét thư mục** (`POST /api/scan/directory`) — model `DirectoryScanRequest` đã khai báo trong `server.py` nhưng chưa có route handler
- [ ] **Thêm `clearHistory()` vào `api.js`** — backend hỗ trợ `DELETE /api/history` nhưng frontend chưa gọi được
- [ ] **Xử lý lỗi khi VT API key hết quota** — hiện chỉ trả `{"error": "Rate limit exceeded"}`, cần fallback sang Layer 3 thay vì dừng
- [ ] **Thêm file size limit cho upload** — ngăn file > 100MB làm crash server (thêm validation trong endpoint `/api/scan/file`)
- [ ] **Viết unit tests** — thư mục `tests/` hiện rỗng (chỉ có `.gitkeep`)
  - [ ] Test `HashEngine.check()` với file sạch và file malware đã biết
  - [ ] Test `HeuristicEngine` với file entropy cao vs thấp
  - [ ] Test `WAFEngine.check_all()` với từng loại attack
  - [ ] Test API endpoints bằng `httpx.AsyncClient` (FastAPI TestClient)

### Frontend (React)

- [ ] **Dashboard: Thêm biểu đồ Recharts** — `recharts` đã cài nhưng chưa dùng ở bất kỳ page nào
  - [ ] Pie chart phân bố threat level (safe/low/medium/high/critical)
  - [ ] Bar chart hoặc line chart xu hướng scan theo thời gian
- [ ] **ScanHistory: Thêm nút xoá lịch sử** — icon `Trash2` đã import nhưng chưa sử dụng, `DELETE /api/history` chưa có trong `api.js`
- [ ] **ScanHistory: Hiển thị lỗi cho user** — hiện chỉ `console.error`, không có error UI
- [ ] **FileScan: Reset file input sau khi scan** — chọn lại cùng file thì `onChange` không fire

---

## 🟡 Ưu tiên trung bình — Nâng chất lượng

### Backend

- [ ] **Logging hệ thống** — thay `print()` bằng `logging` module với levels (INFO, WARNING, ERROR)
- [ ] **Hash Engine: hỗ trợ cả SHA-256 lẫn MD5 đồng thời** — hiện chỉ load 1 loại hash, nên load cả hai để tăng coverage
- [ ] **VT Engine: retry logic** — khi gặp timeout hoặc 429, tự retry sau delay thay vì trả lỗi ngay
- [ ] **Scan report export** — endpoint `GET /api/report/{scan_id}` trả JSON/PDF chi tiết kết quả scan
- [ ] **Persistent storage** — lưu scan history ra file JSON thay vì chỉ in-memory (mất khi restart server)
- [ ] **WAF Engine: thêm SSRF patterns** — hiện chỉ có SQLi/XSS/CMDi/Path Traversal, thiếu SSRF

### Frontend

- [ ] **URL Scan: validate URL format** — hiện chấp nhận mọi string, cần check `http://`/`https://` prefix
- [ ] **FileScan: hiển thị progress từng layer** — thay vì spinner chung, show "Đang quét Layer 1...", "Layer 2..."
- [ ] **FileScan: nút "Scan lại" / "Quét file khác"** — sau khi có kết quả, phải refresh trang mới scan tiếp
- [ ] **ScanHistory: phân trang** — hardcode lấy 100 items, backend hỗ trợ 500
- [ ] **ScanHistory: hiển thị ngày** — hiện chỉ show giờ, không show ngày tháng
- [ ] **ScanHistory: key dùng index** — nên dùng unique ID thay vì array index (`key={i}`)
- [ ] **Dark mode toggle** — hiện fix cứng dark, thêm nút chuyển light/dark
- [ ] **Responsive mobile** — sidebar chưa responsive trên màn hình nhỏ

---

## 🟢 Ưu tiên thấp — Nice-to-have

### Tính năng mới

- [ ] **Real-time notifications** — WebSocket push khi scan xong (thay vì polling)
- [ ] **Batch scan nhiều file** — kéo thả nhiều file cùng lúc, quét tuần tự
- [ ] **So sánh kết quả scan** — cho phép chọn 2 lần scan để so sánh
- [ ] **Phishing URL detection** — ML model detect URL phishing (ngoài VT) → sử dụng thư mục `models/`
- [ ] **YARA rules engine** — thêm Layer 4 quét bằng YARA signatures
- [ ] **API key management UI** — cho phép nhập/thay đổi VT API key từ dashboard thay vì sửa `.env`
- [ ] **Email alert** — gửi email khi phát hiện threat critical
- [ ] **Multi-language UI** — hỗ trợ chuyển đổi Tiếng Việt / English

### DevOps & Deployment

- [ ] **Dockerfile** — containerize backend + frontend
- [ ] **docker-compose.yml** — chạy cả hệ thống bằng 1 lệnh
- [ ] **CI/CD pipeline** — GitHub Actions: lint → test → build → deploy
- [ ] **Production build** — `vite build` + serve static từ FastAPI (loại bỏ cần 2 servers)
- [ ] **Git LFS cho hash DB** — file `md5HashOfVirus.unibit` (~62MB) vượt giới hạn GitHub khuyến nghị
- [ ] **HTTPS** — thêm TLS cho production
- [ ] **Rate limiting middleware** — chống spam API từ bên ngoài (SlowAPI hoặc custom)

### Code Quality

- [ ] **Type hints hoàn chỉnh** — một số hàm còn thiếu return type annotation
- [ ] **Docstrings cho tất cả public methods** — đặc biệt trong `server.py`
- [ ] **ESLint + Prettier** — frontend chưa có linting config
- [ ] **Pre-commit hooks** — black + isort + flake8 cho Python, eslint cho JS
- [ ] **API error handling thống nhất** — tạo exception handler global cho FastAPI
- [ ] **Accessibility (a11y)** — thêm ARIA labels, keyboard navigation cho frontend

---

## 📝 Tài liệu

- [ ] **Bổ sung API docs** — Swagger tự sinh nhưng thiếu description chi tiết cho từng field
- [ ] **Viết CONTRIBUTING.md** — hướng dẫn contribute cho người mới
- [ ] **Architecture diagram** — vẽ sơ đồ kiến trúc hệ thống (draw.io hoặc Mermaid)
- [ ] **Slide thuyết trình** — chuẩn bị slide demo cho hội đồng
- [ ] **Video demo** — record demo quét file + URL + WAF trên web dashboard

---

## 🐛 Bugs đã biết

- [ ] **Hash DB path lồng 2 tầng** — `hash_engine.py` trỏ tới `database/HashDataBase/HashDataBase/Sha256/` (thư mục lồng `HashDataBase` 2 lần), hoạt động nhưng không đẹp
- [ ] **Large file warning trên GitHub** — `legacy/Fortress-original/md5HashOfVirus.unibit` (61.88MB) trigger cảnh báo mỗi lần push
- [ ] **VT URL scan chờ cứng 5s** — `vt_engine.py` dòng `time.sleep(5)` trước khi lấy kết quả, nếu VT chưa xong sẽ thiếu data
- [ ] **Frontend không có error boundary** — React crash sẽ hiện trang trắng thay vì fallback UI

---

## ✅ Đã hoàn thành

- [x] Restructure project từ Fortress → HThuong Antivirus AI
- [x] Hash Engine (Layer 1) — SHA-256 O(1) lookup, ~39K hashes
- [x] VirusTotal Engine (Layer 2) — API v3, rate limiting, caching
- [x] Heuristic Engine (Layer 3) — entropy, patterns, PE analysis
- [x] WAF Engine — SQLi (21), XSS (21), CMDi (16), Path Traversal (8)
- [x] FastAPI server với 7 endpoints
- [x] React dashboard với 5 pages (Dashboard, FileScan, UrlScan, WAF, History)
- [x] Vite proxy config (frontend → backend)
- [x] Dark theme UI (gray-950 + emerald-400)
- [x] `.github/copilot-instructions.md`
- [x] Push lên GitHub (`wasabixxx/HThuong-Antivirus-AI`)
