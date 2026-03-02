# 📋 TODO — HThuong Antivirus AI

> Danh sách công việc để dự án sẵn sàng demo trước hội đồng.
> Cập nhật lần cuối: 2026-03-02 (session 2)

---

## 🟡 Ưu tiên trung bình — Nâng chất lượng

### Backend

- [x] **Logging hệ thống** — thay `print()` bằng `logging` module với levels (INFO, WARNING, ERROR) ✅ Done
- [x] **File size limit cho upload** — ngăn file > 100MB làm crash server ✅ Done (MAX_FILE_SIZE=100MB)
- [x] **VT Engine: retry logic** — khi gặp timeout hoặc 429, tự retry sau delay ✅ Done (3 retries, exponential backoff)
- [x] **WAF Engine: thêm SSRF patterns** — hiện chỉ có SQLi/XSS/CMDi/Path Traversal ✅ Done (20 SSRF patterns, total 87)
- [x] **Persistent storage** — lưu scan history ra file JSON (mất khi restart server) ✅ Done (data/scan_history.json)

### Frontend

- [x] **URL Scan: validate URL format** — check `http://`/`https://` prefix ✅ Done
- [x] **Error Boundary** — React crash sẽ hiện trang trắng, cần fallback UI ✅ Done (ErrorBoundary.jsx)
- [ ] **Dark mode toggle** — hiện fix cứng dark
- [x] **Responsive mobile** — sidebar chưa responsive ✅ Done (mobile overlay + hamburger menu)

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
- [x] WAF Engine — Hybrid: Regex (87 patterns incl. SSRF) + ML (TF-IDF + Random Forest)
- [x] ML WAF Engine — 2,469 augmented payloads (739 raw), 5 classes, 98.58% test accuracy

### ML/AI Improvements (Thesis-ready)
- [x] **WAF Dataset expanded** — 443 → 739 raw → 2,469 augmented (URL-encode, double-encode, case-swap, whitespace)
- [x] **GridSearchCV hyperparameter tuning** — tìm best params tự động (300 trees, no max_depth)
- [x] **Feature Importance analysis** — top 30 n-gram features + per-class discriminative features
- [x] **WAF Benchmark updated** — Regex 75.1% | ML **99.6%** | Hybrid **99.6%** accuracy, FPR 0.48%
- [x] **Anomaly Engine Benchmark** — đánh giá trên real system files + synthetic malware (97 files)
- [x] **Thesis figures** — 12 biểu đồ PNG (`thesis_figures/`): confusion matrix, benchmark, feature importance, architecture, dataset distribution, anomaly benchmark...

### Backend (FastAPI)
- [x] FastAPI server với 9 endpoints (health, stats, scan/file, scan/url, scan/directory, waf/check, history GET/DELETE, eicar)
- [x] Endpoint quét thư mục `POST /api/scan/directory` — batch scan + validation
- [x] `clearHistory()` API + `DELETE /api/history`
- [x] VT API quota fallback — Layer 2 skip khi key missing, auto-degrade
- [x] Context-aware Layer 4 — require confidence >= 0.65 khi layers 1-3 clean
- [x] File cleanup — uploaded files scanned then deleted
- [x] Logging module — `logging.basicConfig()` với INFO/WARNING/ERROR
- [x] File size limit — MAX_FILE_SIZE=100MB validation
- [x] VT retry logic — 3 retries w/ exponential backoff (15*2^n on 429, 5*(n+1) on timeout)
- [x] SSRF patterns — 20 patterns (internal IPs, cloud metadata, dangerous schemes, IP encoding bypass)
- [x] Persistent scan history — JSON file (`data/scan_history.json`), load on startup, save on write

### Frontend (React 18 + Vite)
- [x] 6 pages: Dashboard, FileScan, UrlScan, WAFCheck, ScanHistory, DirectoryScan
- [x] Dashboard: 5 biểu đồ Recharts (PieChart, BarChart x3, AreaChart)
- [x] FileScan: Drag-drop + EICAR test button + 4-layer progress animation
- [x] ScanHistory: Bộ lọc nâng cao + CSV/JSON export + nút xoá lịch sử
- [x] PDF export: 5 loại báo cáo (file, URL, WAF, directory, history) — jsPDF + autoTable
- [x] URL validation — check http:///https:// prefix
- [x] Vietnamese UI toàn bộ
- [x] Dark theme (gray-950 + emerald-400)
- [x] Code splitting: main 86KB, pdf 422KB, charts 565KB
- [x] Error Boundary — class component, fallback UI with retry button
- [x] Responsive mobile — slide-in sidebar, overlay backdrop, hamburger header

### ML/AI Models
- [x] WAF ML model — `models/waf/` (waf_rf_model.joblib, tfidf_vectorizer, metadata, benchmark)
- [x] Anomaly model — `models/anomaly/` (isolation_forest.joblib, metadata, benchmark_results)
- [x] WAF Benchmark — Regex 75.1% | ML 99.6% | Hybrid 99.6% accuracy

### Scripts & Tools
- [x] `scripts/generate_thesis_figures.py` — 12 biểu đồ cho luận văn
- [x] `tests/benchmark_waf.py` — so sánh Regex vs ML vs Hybrid WAF
- [x] `tests/benchmark_anomaly.py` — đánh giá Isolation Forest trên file thật
- [x] `src/engine/train_waf_model.py` — training pipeline + GridSearchCV + feature importance

### Infrastructure
- [x] PWA — manifest.json, service worker (network-first API, cache-first static), icons 192+512
- [x] Vite proxy config (frontend → backend)
- [x] Production build — `vite build` + FastAPI serves `frontend/dist/`
- [x] Unit tests — 53 tests across 7 test classes (pytest)
- [x] `.github/copilot-instructions.md` — comprehensive project docs
- [x] Push lên GitHub (`wasabixxx/HThuong-Antivirus-AI`)
