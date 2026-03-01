# 🛡️ HThuong Antivirus AI

> **Tích hợp Trí Tuệ Nhân Tạo để Tăng Cường Bảo Mật trong Ứng Dụng Web**

---

## 🧠 Giới thiệu

**HThuong Antivirus AI** là hệ thống bảo mật web thông minh, kết hợp:

- **VirusTotal API** (70+ AV engines) để phát hiện malware chính xác nhất
- **Hash-based Detection** (local database) để quét offline siêu nhanh
- **Heuristic Analysis** phân tích entropy + pattern đáng ngờ
- **Web Application Firewall** phát hiện SQL Injection & XSS
- **Phishing URL Detection** kiểm tra URL độc hại

Tất cả được gói trong **Web Dashboard** hiện đại với FastAPI backend + React frontend.

---

## ⚙️ Tech Stack

| Category | Technology |
|----------|------------|
| 🔧 Backend | Python 3.10+ / FastAPI / Uvicorn |
| 🤖 AI Engine | VirusTotal API + Local Hash DB + Heuristic |
| 🌐 Frontend | React 18 + TailwindCSS + Recharts |
| 🗄️ Database | Local hash DB (.unibit) + Redis cache |
| 📦 Deploy | Docker (optional) |

---

## 📁 Cấu trúc Project

```
HThuong-Antivirus-AI/
├── src/
│   ├── engine/          # AI Engine core
│   │   ├── vt_engine.py     # VirusTotal integration
│   │   ├── hash_engine.py   # Local hash-based detection
│   │   ├── heuristic.py     # Heuristic analysis
│   │   └── waf.py           # Web Application Firewall
│   ├── api/             # FastAPI REST server
│   │   └── server.py
│   └── database/        # Virus hash databases
├── frontend/            # React web dashboard
├── models/              # ML models (future)
├── tests/               # Unit tests
├── legacy/              # Original Fortress project
└── requirements.txt
```

---

## 🚀 Cài đặt & Chạy

### 1. Cài dependencies

```bash
pip install -r requirements.txt
```

### 2. Chạy Backend API

```bash
cd src/api
uvicorn server:app --reload --port 8000
```

### 3. Chạy Frontend

```bash
cd frontend
npm install
npm run dev
```

### 4. Mở trình duyệt

- **Dashboard**: http://localhost:5173
- **API Docs**: http://localhost:8000/docs

---

## 🔑 Cấu hình API Key

Tạo file `.env` ở thư mục gốc:

```env
VT_API_KEY=your_virustotal_api_key_here
```

Đăng ký miễn phí tại: https://www.virustotal.com

---

## 📊 Tính năng

| Tính năng | Mô tả | Trạng thái |
|-----------|--------|------------|
| 🔍 File Scan | Upload file → quét qua 3 tầng AI | ✅ |
| 🌐 URL Scan | Kiểm tra URL phishing/malicious | ✅ |
| 🛡️ WAF | Phát hiện SQLi, XSS, Command Injection | ✅ |
| 📊 Dashboard | Biểu đồ thống kê realtime | ✅ |
| 📝 Scan History | Lịch sử quét với filter | ✅ |
| 🗑️ Cache Cleaner | Dọn file rác hệ thống | ✅ |

---

## 🏗️ Kiến trúc AI Engine (3 tầng)

```
File Input
    │
    ▼
┌─── Tầng 1: Hash-based (instant, offline) ───┐
│  SHA-256 hash → lookup trong local DB        │
│  ✓ Match → MALWARE (confidence: 100%)       │
│  ✗ No match → tiếp tầng 2                   │
└──────────────────────────────────────────────┘
    │
    ▼
┌─── Tầng 2: VirusTotal API (70+ engines) ────┐
│  SHA-256 hash → gửi lên VT kiểm tra         │
│  ✓ Malicious → MALWARE (chi tiết AV names)  │
│  ✗ Clean / Not found → tiếp tầng 3          │
└──────────────────────────────────────────────┘
    │
    ▼
┌─── Tầng 3: Heuristic Analysis (offline) ────┐
│  Entropy + Suspicious patterns + PE analysis │
│  Score ≥ 50% → SUSPICIOUS                   │
│  Score < 50% → CLEAN                        │
└──────────────────────────────────────────────┘
```

---

## 👤 Tác giả

**HThuong** – Đồ án: *Tích hợp Trí Tuệ Nhân Tạo để Tăng Cường Bảo Mật trong Ứng Dụng Web*

---

## 📄 License

MIT License
