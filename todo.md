# 📋 TODO — HThuong Antivirus AI

> Danh sách công việc để dự án sẵn sàng demo trước hội đồng.
> Cập nhật lần cuối: 2026-03-02

---

## 🟡 Ưu tiên trung bình — Nâng chất lượng

### Backend

- [ ] **Logging hệ thống** — thay `print()` bằng `logging` module với levels (INFO, WARNING, ERROR)
- [ ] **File size limit cho upload** — ngăn file > 100MB làm crash server
- [ ] **VT Engine: retry logic** — khi gặp timeout hoặc 429, tự retry sau delay
- [ ] **WAF Engine: thêm SSRF patterns** — hiện chỉ có SQLi/XSS/CMDi/Path Traversal
- [ ] **Persistent storage** — lưu scan history ra file JSON (mất khi restart server)

### Frontend

- [ ] **URL Scan: validate URL format** — cần check `http://`/`https://` prefix trước khi gửi
- [ ] **Error Boundary** — React crash sẽ hiện trang trắng, cần fallback UI
- [ ] **Dark mode toggle** — hiện fix cứng dark
- [ ] **Responsive mobile** — sidebar chưa responsive

---

## 🟢 Ưu tiên thấp — Nice-to-have

### Tính năng mới

- [ ] **Real-time notifications** — WebSocket push khi scan xong
- [ ] **Batch scan nhiều file** — kéo thả nhiều file cùng lúc
- [ ] **Phishing URL detection** — ML model detect URL phishing (ngoài VT)
- [ ] **API key management UI** — nhập/thay đổi VT API key từ dashboard

### DevOps & Deployment

- [ ] **Dockerfile + docker-compose** — chạy cả hệ thống bằng 1 lệnh
- [ ] **CI/CD pipeline** — GitHub Actions: lint → test → build → deploy
- [ ] **HTTPS** — thêm TLS cho production
- [ ] **Rate limiting middleware** — SlowAPI hoặc custom

### Code Quality

- [ ] **ESLint + Prettier** — frontend chưa có linting config
- [ ] **Pre-commit hooks** — black + isort + flake8 cho Python
- [ ] **API error handling thống nhất** — exception handler global cho FastAPI

---

## 📝 Tài liệu

- [ ] **Architecture diagram** — sơ đồ kiến trúc 4-layer detection (Mermaid)
- [ ] **Slide thuyết trình** — chuẩn bị slide demo cho hội đồng
- [ ] **Video demo** — record demo quét file + URL + WAF

---

## 🐛 Bugs đã biết

- [ ] **Hash DB path lồng 2 tầng** — `database/HashDataBase/HashDataBase/Sha256/` (thư mục lồng 2 lần)
- [ ] **Large file trên GitHub** — `legacy/md5HashOfVirus.unibit` (~62MB) trigger cảnh báo
- [ ] **VT URL scan chờ cứng 5s** — `time.sleep(5)` có thể thiếu data nếu VT chưa xong

---

## ✅ Đã hoàn thành

### Core Engines
- [x] Hash Engine (Layer 1) — SHA-256 O(1) lookup, ~39K hashes + EICAR test
- [x] VirusTotal Engine (Layer 2) — API v3, rate limiting 15s, caching
- [x] Heuristic Engine (Layer 3) — entropy, 22 malware + 11 network patterns, PE analysis
- [x] Anomaly Engine (Layer 4) — Isolation Forest, 8 features, 740 training samples
- [x] WAF Engine — Hybrid: Regex (67 patterns) + ML (TF-IDF + Random Forest, 97% accuracy)
- [x] ML WAF Engine — 443 labeled payloads, 5 classes (sqli, xss, cmdi, path_traversal, safe)

### Backend (FastAPI)
- [x] FastAPI server với 9 endpoints (health, stats, scan/file, scan/url, scan/directory, waf/check, history GET/DELETE, eicar)
- [x] Endpoint quét thư mục `POST /api/scan/directory` — batch scan + validation
- [x] `clearHistory()` API + `DELETE /api/history`
- [x] VT API quota fallback — Layer 2 skip khi key missing, auto-degrade
- [x] Context-aware Layer 4 — require confidence >= 0.65 khi layers 1-3 clean
- [x] File cleanup — uploaded files scanned then deleted

### Frontend (React 18 + Vite)
- [x] 6 pages: Dashboard, FileScan, UrlScan, WAFCheck, ScanHistory, DirectoryScan
- [x] Dashboard: 5 biểu đồ Recharts (PieChart, BarChart x3, AreaChart)
- [x] FileScan: Drag-drop + EICAR test button + 4-layer progress animation
- [x] ScanHistory: Bộ lọc nâng cao + CSV/JSON export + nút xoá lịch sử
- [x] PDF export: 5 loại báo cáo (file, URL, WAF, directory, history) — jsPDF + autoTable
- [x] Vietnamese UI toàn bộ
- [x] Dark theme (gray-950 + emerald-400)
- [x] Code splitting: main 86KB, pdf 422KB, charts 565KB

### ML/AI Models
- [x] WAF ML model — `models/waf/` (waf_rf_model.joblib, tfidf_vectorizer, metadata, benchmark)
- [x] Anomaly model — `models/anomaly/` (isolation_forest.joblib, metadata)
- [x] WAF Benchmark — Regex 80.8% | ML 98.4% | Hybrid 97.1% accuracy

### Infrastructure
- [x] PWA — manifest.json, service worker (network-first API, cache-first static), icons 192+512
- [x] Vite proxy config (frontend → backend)
- [x] Production build — `vite build` + FastAPI serves `frontend/dist/`
- [x] Unit tests — 53 tests across 7 test classes (pytest)
- [x] `.github/copilot-instructions.md` — comprehensive project docs
- [x] Push lên GitHub (`wasabixxx/HThuong-Antivirus-AI`)
