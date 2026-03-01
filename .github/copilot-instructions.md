# GitHub Copilot Instructions — HThuong Antivirus AI

## Project Overview

**HThuong Antivirus AI** is an AI-powered web security platform that provides multi-layered threat detection through a modern web dashboard. It combines VirusTotal API integration with local hash-based detection, heuristic analysis, and a Web Application Firewall (WAF).

- **Tên đề tài**: Tích hợp Trí Tuệ Nhân Tạo để Tăng Cường Bảo Mật trên nền Web
- **Tên báo cáo (đầy đủ)**: Tích hợp Trí Tuệ Nhân Tạo để Tăng Cường Bảo Mật trong Ứng Dụng Di Động và Web

- **Repository**: `wasabixxx/HThuong-Antivirus-AI`
- **Language**: Vietnamese comments throughout codebase (this is intentional)
- **Status**: Active development — academic/thesis project

---

## Architecture

```
HThuong-Antivirus-AI/
├── src/
│   ├── engine/                 # Core detection engines (Python)
│   │   ├── hash_engine.py      # Layer 1 — Local SHA-256/MD5 hash lookup (O(1) set)
│   │   ├── vt_engine.py        # Layer 2 — VirusTotal API v3 integration
│   │   ├── heuristic.py        # Layer 3 — Entropy + pattern-based analysis
│   │   ├── anomaly_engine.py   # Layer 4 — Isolation Forest anomaly detection (ML)
│   │   ├── waf.py              # WAF — Hybrid regex + ML attack detection
│   │   ├── ml_waf.py           # ML WAF — TF-IDF + Random Forest classifier
│   │   ├── waf_dataset.py      # Training dataset for ML WAF (443 payloads)
│   │   └── train_waf_model.py  # Training script for ML WAF model
│   ├── api/
│   │   └── server.py           # FastAPI REST server (all endpoints under /api/)
│   └── database/
│       └── HashDataBase/       # Local virus hash databases (.unibit files)
├── frontend/                   # React 18 SPA (Vite + TailwindCSS)
│   └── src/
│       ├── App.jsx             # Main layout — sidebar navigation, dark theme
│       ├── api.js              # API client module (fetch-based, /api prefix)
│       └── pages/              # 6 page components
│           ├── Dashboard.jsx   # Stats overview + engine status
│           ├── FileScan.jsx    # Drag-drop file upload → 4-layer scan
│           ├── DirectoryScan.jsx # Directory path → batch scan
│           ├── UrlScan.jsx     # URL input → VirusTotal URL analysis
│           ├── WAFCheck.jsx    # Payload testing with ML analysis display
│           └── ScanHistory.jsx # Filterable scan log
├── models/                     # Trained ML models
│   ├── waf/                    # WAF ML model (TF-IDF + Random Forest)
│   │   ├── waf_rf_model.joblib
│   │   ├── waf_tfidf_vectorizer.joblib
│   │   ├── waf_model_metadata.json
│   │   └── benchmark_results.json
│   └── anomaly/                # Anomaly Detection model (Isolation Forest)
│       ├── isolation_forest.joblib
│       └── anomaly_metadata.json
├── tests/                      # Tests & benchmarks
│   └── benchmark_waf.py        # Regex vs ML vs Hybrid benchmark
├── legacy/                     # Original Fortress desktop project (DO NOT MODIFY)
├── .env                        # VT_API_KEY (never committed)
└── requirements.txt            # Python dependencies
```

---

## Tech Stack

| Layer      | Technology                                  |
| ---------- | ------------------------------------------- |
| Backend    | Python 3.10+ · FastAPI 0.115+ · Uvicorn     |
| Frontend   | React 18 · Vite 6 · TailwindCSS 3 · Recharts |
| Icons      | lucide-react                                |
| Detection  | VirusTotal API v3 · Local Hash DB · Heuristic |
| ML/AI      | scikit-learn (TF-IDF + RF, Isolation Forest) |
| WAF        | Hybrid: Regex patterns + ML classifier      |
| Build      | pip (backend) · npm (frontend)              |

---

## 4-Layer Detection Engine

All file scans pass through layers **sequentially** — early exit on first detection:

1. **Layer 1 — Hash Local (instant, offline)**
   - `HashEngine` loads ~39,000 SHA-256 hashes into a Python `set()` for O(1) lookup.
   - Source: `.unibit` files in `src/database/HashDataBase/`.
   - If hash matches → return immediately, skip layers 2–4.

2. **Layer 2 — VirusTotal API (cloud, 70+ AV engines)**
   - `VirusTotalEngine` sends file hash to VT API v3 (does NOT upload file by default).
   - Rate limited: 15s minimum between calls (free tier = 4 req/min, 500/day).
   - Results are cached in-memory by SHA-256 hash.
   - If detected → return immediately, skip layers 3–4.

3. **Layer 3 — Heuristic (offline fallback)**
   - `HeuristicEngine` calculates Shannon entropy, scans for suspicious patterns (22 malware patterns + 11 network patterns), and checks PE headers.
   - Score-based: threshold = 50 for detection.
   - Used when VT returns clean or is unavailable.

4. **Layer 4 — Anomaly Detection (ML, offline)**
   - `AnomalyEngine` uses **Isolation Forest** (unsupervised ML) to detect anomalous files.
   - Extracts 8 features: entropy, file_size, suspicious_patterns, network_patterns, is_pe, null_byte_ratio, printable_ratio, unique_bytes.
   - Pre-trained baseline model (525 samples). No labeled malware data needed.
   - Acts as final safety net when all other layers return clean.

---

## ML/AI Components

### ML WAF Engine (TF-IDF + Random Forest)
- **File**: `src/engine/ml_waf.py`
- **Training**: `src/engine/train_waf_model.py`
- **Dataset**: `src/engine/waf_dataset.py` (443 labeled payloads)
- **Pipeline**: TF-IDF character n-grams (2-5) → Random Forest (200 trees)
- **Classes**: sqli, xss, cmdi, path_traversal, safe
- **Accuracy**: ~92% test, ~98% on full dataset
- **Integration**: Hybrid with regex WAF — ML supplements regex detection
- **Models saved**: `models/waf/`

### Anomaly Detection Engine (Isolation Forest)
- **File**: `src/engine/anomaly_engine.py`
- **Approach**: Unsupervised — learns "normal" file profile, flags outliers
- **Features**: 8 numeric features extracted from binary file content
- **Contamination**: 5% (assumes ~5% anomaly rate)
- **Auto-trains** baseline on first run if no saved model exists
- **Models saved**: `models/anomaly/`

### Benchmark
- **File**: `tests/benchmark_waf.py`
- **Compares**: Regex-only vs ML-only vs Hybrid WAF
- **Output**: accuracy, precision, recall, F1, confusion matrix, detection rate
- **Results saved**: `models/waf/benchmark_results.json`

---

## API Endpoints

All routes are prefixed with `/api/`:

| Method   | Endpoint             | Purpose                                |
| -------- | -------------------- | -------------------------------------- |
| `GET`    | `/api/health`        | Engine status, hash DB size, ML info   |
| `GET`    | `/api/stats`         | Scan statistics since server start     |
| `POST`   | `/api/scan/file`     | Upload file → 4-layer scan            |
| `POST`   | `/api/scan/url`      | URL → VirusTotal URL analysis          |
| `POST`   | `/api/scan/directory` | Directory path → batch file scan      |
| `POST`   | `/api/waf/check`     | Test payload (hybrid regex + ML)       |
| `GET`    | `/api/history`       | Get scan history (newest first)        |
| `DELETE` | `/api/history`       | Clear scan history                     |

- Interactive API docs: `http://localhost:8000/docs`
- Scan history is in-memory (max 500 records, FIFO eviction).

---

## Coding Conventions

### Python (Backend)

- Follow **PEP 8** style.
- Use **type hints** for all function signatures (e.g., `def check(self, file_path: str) -> dict:`).
- Use `async/await` for all FastAPI endpoint handlers.
- Every engine class must have a `check()` method returning a **standardized result dict**:
  ```python
  {
      "detected": bool,        # Was a threat found?
      "method": str,           # "hash_local" | "virustotal" | "heuristic" | "anomaly_detection" | "waf"
      "confidence": float,     # 0.0–1.0
      "threat_level": str,     # "safe" | "low" | "medium" | "high" | "critical"
      "details": dict | None,  # Engine-specific details
  }
  ```
- Comments and docstrings can be in **Vietnamese** — this is intentional for the thesis.
- Import order: stdlib → third-party → local modules.
- Use `os.path.join()` for all file paths (cross-platform).
- Never hardcode API keys — always read from `.env` via `python-dotenv`.

### JavaScript/React (Frontend)

- **Functional components** with hooks only (no class components).
- File naming: PascalCase for components (`FileScan.jsx`), camelCase for utilities (`api.js`).
- All API calls go through `frontend/src/api.js` — never call `fetch()` directly from components.
- API base URL is `/api` (proxied by Vite dev server to `localhost:8000`).
- UI theme: **dark mode** (gray-950 background, gray-900 surfaces, emerald-400 accent).
- Use TailwindCSS utility classes — no custom CSS unless absolutely necessary.
- Icons from `lucide-react` only.

---

## Environment Variables

```env
VT_API_KEY=<your-virustotal-api-key>   # Required for Layer 2 + URL scan
```

- Stored in `.env` at project root.
- Listed in `.gitignore` — **never commit**.
- Server gracefully degrades if VT key is missing (Layer 2 skipped, URL scan returns 503).

---

## Running the Project

### Backend

```bash
pip install -r requirements.txt
cd src/api
uvicorn server:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev       # Vite dev server on http://localhost:5173
```

- Vite proxies `/api` requests to `http://localhost:8000` (configured in `vite.config.js`).

---

## Key Design Decisions (must be preserved)

1. **Sequential layer execution with early exit** — do NOT parallelize layers; hash check must run first to save VT API quota.
2. **Hash-first approach** — local detection is free and instant; always check local DB before calling any external API.
3. **VT rate limiting** — 15-second minimum gap between API calls. Never remove or reduce this.
4. **In-memory caching** — VT results are cached by hash. No external cache (Redis) yet.
5. **File cleanup** — uploaded files are saved to temp, scanned, then deleted. Never persist uploaded files.
6. **CORS allow all** — intentional for development. Tighten before production.
7. **No authentication** — thesis/demo project. Auth is not in scope.

---

## Common Development Tasks

### Adding a new detection engine

1. Create a new class in `src/engine/` with a `check(file_path: str) -> dict` method.
2. Initialize it in `src/api/server.py` alongside existing engines.
3. Add it as a new layer in the `/api/scan/file` endpoint (respect sequential order).
4. Add corresponding frontend display in `FileScan.jsx`.

### Adding a new API endpoint

1. Define Pydantic model in `src/api/server.py` if needed.
2. Add the route handler (`@app.get` / `@app.post`).
3. Add the API function in `frontend/src/api.js`.
4. Create or update the relevant page component in `frontend/src/pages/`.

### Adding a new frontend page

1. Create component in `frontend/src/pages/NewPage.jsx`.
2. Add navigation entry in `NAV_ITEMS` array in `App.jsx`.
3. Add case to `renderPage()` switch in `App.jsx`.
4. Add icon import from `lucide-react`.

### Updating the hash database

- Hash files are plain text, one hash per line, stored in `src/database/HashDataBase/`.
- `virusHash.unibit` — SHA-256 hashes.
- `virusInfo.unibit` — corresponding malware names (same line index).
- `md5HashOfVirus.unibit` — MD5 hashes (large file, ~62MB).

---

## WAF Engine Patterns

The WAF detects 4 categories of web attacks via regex:

| Category           | Pattern count | Examples                              |
| ------------------ | ------------- | ------------------------------------- |
| SQL Injection      | 21 patterns   | `' OR 1=1--`, `UNION SELECT`, `DROP TABLE` |
| XSS                | 21 patterns   | `<script>`, `javascript:`, `onerror=` |
| Command Injection  | 16 patterns   | `; ls`, `$(cmd)`, `` `whoami` ``      |
| Path Traversal     | 8 patterns    | `../../etc/passwd`, `..\\windows`     |

When adding new WAF patterns:
- Add regex to the appropriate list in `src/engine/waf.py`.
- Use raw strings (`r"..."`) for all regex patterns.
- Use `re.IGNORECASE` flag (already applied in `check_all()`).

---

## Things to AVOID

- **Do NOT modify files in `legacy/`** — these are the original Fortress project files preserved for reference.
- **Do NOT remove rate limiting** on VT engine — the free tier will get blocked.
- **Do NOT use external databases** (PostgreSQL, MongoDB) — keep it simple with in-memory + file-based storage for now.
- **Do NOT add authentication** unless explicitly requested — this is a demo project.
- **Do NOT switch from TailwindCSS** to another CSS framework.
- **Do NOT upload large files to VT** unless the user explicitly wants it — always try hash-only scan first.

---

## Dependencies

### Python (`requirements.txt`)

| Package            | Purpose                          |
| ------------------ | -------------------------------- |
| fastapi            | REST API framework               |
| uvicorn[standard]  | ASGI server                      |
| requests           | HTTP client for VT API           |
| python-dotenv      | Load `.env` environment vars     |
| python-multipart   | File upload support for FastAPI  |
| numpy              | Numerical operations (heuristic) |
| scikit-learn       | ML models (RF, Isolation Forest, TF-IDF) |
| joblib             | Model serialization              |

### Node.js (`frontend/package.json`)

| Package            | Purpose                          |
| ------------------ | -------------------------------- |
| react / react-dom  | UI framework                     |
| recharts           | Dashboard charts                 |
| lucide-react       | Icon library                     |
| tailwindcss        | Utility-first CSS                |
| vite               | Build tool + dev server          |
| @vitejs/plugin-react | React fast refresh             |

---

## IMPORTANT — Keep This File Updated

**Copilot must update this `copilot-instructions.md` file whenever there are significant changes to the project**, including but not limited to:

- Adding new engines, API endpoints, or frontend pages
- Changing the architecture or file structure
- Adding new dependencies (Python or Node.js)
- Modifying coding conventions or design decisions
- Adding new WAF patterns or detection layers
- Any change that would affect how Copilot should assist with this project

This ensures Copilot always has accurate context about the current state of the project.
