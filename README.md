# 🛡️ HThuong Antivirus AI

> **Tích hợp Trí Tuệ Nhân Tạo để Tăng Cường Bảo Mật trên nền Web**
>
> Tên báo cáo đầy đủ: *Tích hợp Trí Tuệ Nhân Tạo để Tăng Cường Bảo Mật trong Ứng Dụng Di Động và Web*

---

## 🧠 Giới thiệu

**HThuong Antivirus AI** là nền tảng bảo mật web thông minh sử dụng AI/ML đa tầng, bao gồm:

- **4 tầng quét file**: Hash Local → VirusTotal API → Heuristic → AI Anomaly Detection
- **Hybrid WAF**: Regex patterns + ML classifier (TF-IDF + Random Forest) phát hiện SQLi, XSS, Command Injection, Path Traversal
- **Anomaly Detection**: Isolation Forest (unsupervised ML) — phát hiện file bất thường không cần dữ liệu malware có nhãn
- **VirusTotal Integration**: 70+ AV engines cho phát hiện chính xác nhất
- **Web Dashboard**: Giao diện dark-mode hiện đại với React + TailwindCSS

---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|------------|
| 🔧 Backend | Python 3.10+ · FastAPI 0.115+ · Uvicorn |
| 🤖 AI/ML | scikit-learn (TF-IDF + Random Forest, Isolation Forest) |
| 🌐 Frontend | React 18 · Vite 6 · TailwindCSS 3 · Recharts |
| 🔍 Detection | VirusTotal API v3 · Local Hash DB · Heuristic · Anomaly ML |
| 🛡️ WAF | Hybrid: 66 regex patterns + ML classifier (443 training samples) |
| 📦 Icons | lucide-react |

---

## 📁 Cấu trúc Project

```
HThuong-Antivirus-AI/
├── src/
│   ├── engine/                    # Core detection engines
│   │   ├── hash_engine.py         # Tầng 1 — SHA-256/MD5 hash lookup (O(1) set)
│   │   ├── vt_engine.py           # Tầng 2 — VirusTotal API v3
│   │   ├── heuristic.py           # Tầng 3 — Entropy + pattern analysis
│   │   ├── anomaly_engine.py      # Tầng 4 — Isolation Forest anomaly detection
│   │   ├── waf.py                 # WAF — Hybrid regex + ML
│   │   ├── ml_waf.py              # ML WAF — TF-IDF + Random Forest classifier
│   │   ├── waf_dataset.py         # Training dataset (443 labeled payloads)
│   │   └── train_waf_model.py     # Training script for ML WAF
│   ├── api/
│   │   └── server.py              # FastAPI REST server
│   └── database/
│       └── HashDataBase/          # Local virus hash databases (.unibit)
├── frontend/                      # React 18 SPA (Vite + TailwindCSS)
│   └── src/
│       ├── App.jsx                # Main layout — sidebar, dark theme
│       ├── api.js                 # API client module
│       └── pages/                 # 6 page components
│           ├── Dashboard.jsx      # Stats + engine status + ML model info
│           ├── FileScan.jsx       # File upload → 4-layer scan
│           ├── DirectoryScan.jsx  # Directory path → batch scan
│           ├── UrlScan.jsx        # URL → VirusTotal analysis
│           ├── WAFCheck.jsx       # Payload testing + ML analysis display
│           └── ScanHistory.jsx    # Filterable scan log
├── models/                        # Trained ML models
│   ├── waf/                       # TF-IDF + Random Forest (WAF)
│   │   ├── waf_rf_model.joblib
│   │   ├── waf_tfidf_vectorizer.joblib
│   │   └── waf_model_metadata.json
│   └── anomaly/                   # Isolation Forest (file anomaly)
│       ├── isolation_forest.joblib
│       └── anomaly_metadata.json
├── tests/                         # Benchmarks & tests
│   └── benchmark_waf.py           # Regex vs ML vs Hybrid comparison
├── legacy/                        # Original Fortress project (reference only)
├── .env                           # VT_API_KEY (not committed)
└── requirements.txt
```

---

## 🚀 Cài đặt & Chạy

### 1. Backend

```bash
pip install -r requirements.txt
cd src/api
uvicorn server:app --reload --port 8000
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

### 3. Mở trình duyệt

| URL | Mô tả |
|-----|--------|
| http://localhost:5173 | Web Dashboard |
| http://localhost:8000/docs | Interactive API Docs |

---

## 🔑 Cấu hình

Tạo file `.env` ở thư mục gốc:

```env
VT_API_KEY=your_virustotal_api_key_here
```

> Đăng ký miễn phí: https://www.virustotal.com
>
> Server vẫn hoạt động nếu không có key — Tầng 2 (VirusTotal) sẽ bị bỏ qua, URL Scan trả về 503.

---

## 🏗️ Kiến trúc AI Engine (4 tầng)

Quét file tuần tự — **early exit** khi phát hiện mối đe dọa ở bất kỳ tầng nào:

```
File Input
    │
    ▼
┌─── Tầng 1: Hash Local (instant, offline) ────────┐
│  SHA-256 hash → lookup O(1) trong local DB        │
│  ~39,000 hashes loaded                            │
│  ✓ Match → MALWARE (confidence: 100%) → STOP     │
│  ✗ No match → tiếp tầng 2                        │
└───────────────────────────────────────────────────┘
    │
    ▼
┌─── Tầng 2: VirusTotal API (cloud, 70+ engines) ──┐
│  SHA-256 hash → gửi lên VT API v3 (hash-only)    │
│  Rate limited: 15s gap (free tier: 4 req/min)     │
│  Cache in-memory by hash                          │
│  ✓ Malicious → MALWARE + chi tiết AV → STOP      │
│  ✗ Clean → tiếp tầng 3                           │
└───────────────────────────────────────────────────┘
    │
    ▼
┌─── Tầng 3: Heuristic Analysis (offline) ──────────┐
│  Shannon entropy + 22 malware patterns             │
│  + 11 network patterns + PE header check           │
│  Score ≥ 50 → SUSPICIOUS → STOP                   │
│  Score < 50 → tiếp tầng 4                         │
└────────────────────────────────────────────────────┘
    │
    ▼
┌─── Tầng 4: AI Anomaly Detection (ML, offline) ────┐
│  Isolation Forest (unsupervised ML)                │
│  8 features: entropy, file_size, suspicious_       │
│    patterns, network_patterns, is_pe,              │
│    null_byte_ratio, printable_ratio, unique_bytes  │
│  Pre-trained baseline: 525 samples                 │
│  ✓ Anomaly → SUSPICIOUS                           │
│  ✗ Normal → CLEAN                                 │
└────────────────────────────────────────────────────┘
```

---

## 🛡️ Hybrid WAF (Regex + ML)

Phát hiện 4 loại tấn công web:

| Loại tấn công | Regex Patterns | ML Class |
|----------------|---------------|----------|
| SQL Injection | 21 patterns | `sqli` |
| Cross-Site Scripting (XSS) | 21 patterns | `xss` |
| Command Injection | 16 patterns | `cmdi` |
| Path Traversal | 8 patterns | `path_traversal` |

### ML Pipeline
- **Vectorizer**: TF-IDF character n-grams (2-5)
- **Classifier**: Random Forest (200 trees)
- **Dataset**: 443 labeled payloads (5 classes)
- **Test Accuracy**: ~92%

### Hybrid Logic
1. Nếu regex phát hiện ≤1 rule **VÀ** ML phán "safe" với ≥70% confidence → ML override (giảm false positive)
2. Nếu regex clean nhưng ML phát hiện tấn công → ML bổ sung detection
3. Nếu cả regex + ML đều phát hiện → block ngay

### Benchmark Results

| Metric | Regex-only | ML-only | Hybrid |
|--------|-----------|---------|--------|
| Accuracy | 79.5% | **98.4%** | 91.9% |
| Detection Rate | 85.4% | **99.7%** | 97.3% |
| False Positive Rate | 14.8% | **0.9%** | **0.9%** |
| Macro F1 | 0.80 | **0.98** | 0.92 |
| Speed | **16,124**/sec | 19/sec | 18/sec |

> Hybrid kết hợp tốc độ regex với độ chính xác ML — FPR chỉ 0.9% trong khi vẫn phát hiện 97.3% tấn công.

---

## 📊 Tính năng

| Tính năng | Mô tả | Trạng thái |
|-----------|--------|------------|
| 🔍 File Scan | Upload file → quét qua 4 tầng AI | ✅ |
| 📂 Directory Scan | Quét hàng loạt file trong thư mục | ✅ |
| 🌐 URL Scan | Kiểm tra URL qua VirusTotal | ✅ |
| 🛡️ WAF Test | Test payload — Hybrid regex + ML analysis | ✅ |
| 📊 Dashboard | Stats, engine status, ML model info | ✅ |
| 📝 Scan History | Lịch sử quét với bộ lọc | ✅ |

---

## 🔌 API Endpoints

| Method | Endpoint | Mô tả |
|--------|----------|--------|
| `GET` | `/api/health` | Engine status, hash DB size, ML info |
| `GET` | `/api/stats` | Thống kê scan |
| `POST` | `/api/scan/file` | Upload file → 4-layer scan |
| `POST` | `/api/scan/url` | URL → VirusTotal analysis |
| `POST` | `/api/scan/directory` | Quét hàng loạt file trong thư mục |
| `POST` | `/api/waf/check` | Test WAF payload (hybrid) |
| `GET` | `/api/history` | Lịch sử scan |
| `DELETE` | `/api/history` | Xóa lịch sử |

---

## 🧪 Chạy Benchmark

```bash
# So sánh Regex vs ML vs Hybrid WAF
python tests/benchmark_waf.py

# Train lại ML WAF model (sau khi thêm dataset)
python src/engine/train_waf_model.py
```

---

## 📦 Dependencies

### Python

| Package | Mục đích |
|---------|----------|
| fastapi | REST API framework |
| uvicorn[standard] | ASGI server |
| requests | HTTP client cho VT API |
| python-dotenv | Load .env |
| python-multipart | File upload support |
| numpy | Numerical operations |
| scikit-learn | ML models (RF, Isolation Forest, TF-IDF) |
| joblib | Model serialization |

### Node.js

| Package | Mục đích |
|---------|----------|
| react / react-dom | UI framework |
| recharts | Dashboard charts |
| lucide-react | Icons |
| tailwindcss | Utility-first CSS |
| vite | Build tool + dev server |

---

## 👤 Tác giả

**HThuong** — Đồ án tốt nghiệp: *Tích hợp Trí Tuệ Nhân Tạo để Tăng Cường Bảo Mật trong Ứng Dụng Di Động và Web*

---

## 📄 License

MIT License
