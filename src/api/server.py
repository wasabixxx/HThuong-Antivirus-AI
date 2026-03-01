"""
HThuong Antivirus AI — FastAPI REST Server
Cung cấp API cho Web Dashboard
"""

import os
import sys
import time
import tempfile
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

# Load .env
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

# Add engine to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.hash_engine import HashEngine
from engine.vt_engine import VirusTotalEngine
from engine.heuristic import HeuristicEngine
from engine.waf import WAFEngine
from engine.ml_waf import MLWAFEngine
from engine.anomaly_engine import AnomalyEngine

# ============================================================
# APP SETUP
# ============================================================

app = FastAPI(
    title="HThuong Antivirus AI",
    description="AI-powered Web Security Platform — VirusTotal + Hash DB + Heuristic + WAF",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# ENGINE INIT
# ============================================================

VT_API_KEY = os.getenv("VT_API_KEY", "")

hash_engine = HashEngine("sha256")
vt_engine = VirusTotalEngine(VT_API_KEY) if VT_API_KEY else None
heuristic_engine = HeuristicEngine()
waf_engine = WAFEngine()
ml_waf_engine = MLWAFEngine()
anomaly_engine = AnomalyEngine()

# In-memory scan history
scan_history: list[dict] = []
stats = {
    "total_scans": 0,
    "threats_detected": 0,
    "files_scanned": 0,
    "urls_scanned": 0,
    "waf_checks": 0,
    "waf_blocked": 0,
    "start_time": datetime.now().isoformat(),
}

# ============================================================
# MODELS
# ============================================================

class URLRequest(BaseModel):
    url: str

class WAFRequest(BaseModel):
    payload: str

class DirectoryScanRequest(BaseModel):
    path: str

# ============================================================
# API ENDPOINTS
# ============================================================

@app.get("/api/health")
async def health():
    return {
        "status": "running",
        "version": "2.0.0",
        "engines": {
            "hash_db": len(hash_engine.hash_set),
            "virustotal": vt_engine is not None,
            "heuristic": True,
            "waf": True,
            "ml_waf": ml_waf_engine.is_loaded,
            "anomaly_detection": anomaly_engine.is_loaded,
        },
        "ml_waf_info": ml_waf_engine.get_model_info(),
        "anomaly_info": anomaly_engine.get_model_info(),
        "vt_cache_size": len(vt_engine.cache) if vt_engine else 0,
    }


@app.get("/api/stats")
async def get_stats():
    return {
        **stats,
        "vt_cache_size": len(vt_engine.cache) if vt_engine else 0,
        "history_count": len(scan_history),
    }


@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...)):
    """
    Quét file qua 4 tầng:
      1. Hash local DB
      2. VirusTotal API
      3. Heuristic analysis
      4. Anomaly Detection (Isolation Forest ML)
    """
    start = time.time()

    # Save temp file
    content = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix="_" + (file.filename or "unknown")) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = {
            "filename": file.filename,
            "file_size": len(content),
            "scan_time": 0,
            "layers": {},
        }

        # === LAYER 1: Hash local ===
        hash_result = hash_engine.check(tmp_path)
        result["layers"]["hash_local"] = hash_result

        if hash_result["detected"]:
            result.update({
                "detected": True,
                "method": "hash_local",
                "confidence": 1.0,
                "threat_level": "critical",
                "threat_name": hash_result.get("threat_name"),
                "message": "Known malware detected (local database)",
            })
            _record_scan(result, "file", start)
            return result

        # === LAYER 2: VirusTotal ===
        if vt_engine:
            file_hash = hash_result.get("hash", "")
            vt_result = vt_engine.scan_by_hash(file_hash=file_hash)
            result["layers"]["virustotal"] = vt_result

            if "error" not in vt_result and vt_result.get("detected"):
                result.update({
                    "detected": True,
                    "method": "virustotal",
                    "confidence": vt_result.get("confidence", 0),
                    "threat_level": vt_result.get("threat_level", "high"),
                    "threat_name": vt_result.get("threat_name"),
                    "vt_link": vt_result.get("vt_link"),
                    "vt_stats": vt_result.get("stats"),
                    "message": f"Malware detected by {vt_result.get('stats', {}).get('malicious', 0)} AV engines",
                })
                _record_scan(result, "file", start)
                return result

        # === LAYER 3: Heuristic ===
        heur_result = heuristic_engine.check(tmp_path)
        result["layers"]["heuristic"] = heur_result

        if heur_result["detected"]:
            result.update({
                "detected": True,
                "method": "heuristic",
                "confidence": heur_result.get("confidence", 0),
                "threat_level": heur_result.get("threat_level", "medium"),
                "reasons": heur_result.get("reasons", []),
                "message": "Suspicious file detected by heuristic analysis",
            })
            # Vẫn chạy anomaly để bổ sung thông tin ML
            if anomaly_engine.is_loaded:
                anomaly_result = anomaly_engine.check(tmp_path)
                result["layers"]["anomaly_detection"] = anomaly_result
            _record_scan(result, "file", start)
            return result

        # === LAYER 4: Anomaly Detection (Isolation Forest) ===
        if anomaly_engine.is_loaded:
            anomaly_result = anomaly_engine.check(tmp_path)
            result["layers"]["anomaly_detection"] = anomaly_result

            if anomaly_result.get("detected"):
                result.update({
                    "detected": True,
                    "method": "anomaly_detection",
                    "confidence": anomaly_result.get("confidence", 0),
                    "threat_level": anomaly_result.get("threat_level", "medium"),
                    "anomaly_score": anomaly_result.get("anomaly_score"),
                    "message": "Anomalous file detected by AI (Isolation Forest)",
                })
                _record_scan(result, "file", start)
                return result

        # === ALL CLEAR ===
        vt_info = result["layers"].get("virustotal", {})
        vt_stats = vt_info.get("stats", {})

        result.update({
            "detected": False,
            "method": "all_clear",
            "confidence": 0.0,
            "threat_level": "safe",
            "message": "No threats detected",
            "vt_stats": vt_stats if vt_stats else None,
            "vt_link": vt_info.get("vt_link"),
        })

        _record_scan(result, "file", start)
        return result

    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


@app.post("/api/scan/url")
async def scan_url(req: URLRequest):
    """Quét URL bằng VirusTotal"""
    start = time.time()

    if not vt_engine:
        raise HTTPException(status_code=503, detail="VirusTotal API key not configured")

    result = vt_engine.scan_url(req.url)
    result["scan_time"] = round(time.time() - start, 2)

    _record_scan(result, "url", start)
    return result


@app.post("/api/scan/directory")
async def scan_directory(req: DirectoryScanRequest):
    """
    Quét toàn bộ file trong thư mục.
    Chỉ dùng Layer 1 (Hash) + Layer 3 (Heuristic) + Layer 4 (Anomaly)
    để tránh rate limit VirusTotal.
    """
    start = time.time()

    dir_path = req.path
    if not os.path.isdir(dir_path):
        raise HTTPException(status_code=400, detail=f"Directory not found: {dir_path}")

    results = []
    threats_found = 0
    files_scanned = 0
    max_files = 200  # Giới hạn số file quét

    for root, dirs, files in os.walk(dir_path):
        for fname in files:
            if files_scanned >= max_files:
                break

            fpath = os.path.join(root, fname)
            try:
                file_size = os.path.getsize(fpath)
                if file_size == 0 or file_size > 50 * 1024 * 1024:  # Skip empty & >50MB
                    continue
            except OSError:
                continue

            files_scanned += 1
            file_result = {
                "filename": fname,
                "path": fpath,
                "file_size": file_size,
            }

            # Layer 1: Hash check
            hash_result = hash_engine.check(fpath)
            file_result["hash"] = hash_result.get("hash")

            if hash_result["detected"]:
                file_result.update({
                    "detected": True,
                    "method": "hash_local",
                    "confidence": 1.0,
                    "threat_level": "critical",
                    "threat_name": hash_result.get("threat_name"),
                })
                threats_found += 1
                results.append(file_result)
                continue

            # Layer 3: Heuristic
            heur_result = heuristic_engine.check(fpath)
            if heur_result["detected"]:
                file_result.update({
                    "detected": True,
                    "method": "heuristic",
                    "confidence": heur_result.get("confidence", 0),
                    "threat_level": heur_result.get("threat_level", "medium"),
                    "reasons": heur_result.get("reasons", []),
                })
                threats_found += 1
                results.append(file_result)
                continue

            # Layer 4: Anomaly Detection
            if anomaly_engine.is_loaded:
                anomaly_result = anomaly_engine.check(fpath)
                if anomaly_result.get("detected"):
                    file_result.update({
                        "detected": True,
                        "method": "anomaly_detection",
                        "confidence": anomaly_result.get("confidence", 0),
                        "threat_level": anomaly_result.get("threat_level", "medium"),
                        "anomaly_score": anomaly_result.get("anomaly_score"),
                    })
                    threats_found += 1
                    results.append(file_result)
                    continue

            # Clean
            file_result.update({
                "detected": False,
                "method": "all_clear",
                "threat_level": "safe",
            })
            results.append(file_result)

        if files_scanned >= max_files:
            break

    scan_time = round(time.time() - start, 3)

    summary = {
        "directory": dir_path,
        "files_scanned": files_scanned,
        "threats_found": threats_found,
        "scan_time": scan_time,
        "max_files": max_files,
        "results": results,
    }

    stats["total_scans"] += 1
    stats["files_scanned"] += files_scanned
    stats["threats_detected"] += threats_found

    return summary


@app.post("/api/waf/check")
async def waf_check(req: WAFRequest):
    """Kiểm tra payload qua WAF (SQLi, XSS, Command Injection)"""
    start = time.time()

    result = waf_engine.check_all(req.payload, ml_engine=ml_waf_engine)
    result["scan_time"] = round(time.time() - start, 4)

    stats["waf_checks"] += 1
    if result["detected"]:
        stats["waf_blocked"] += 1

    _record_scan(result, "waf", start)
    return result


@app.get("/api/history")
async def get_history(limit: int = 50):
    """Lấy lịch sử scan"""
    return {
        "total": len(scan_history),
        "items": scan_history[-limit:][::-1],  # newest first
    }


@app.delete("/api/history")
async def clear_history():
    """Xóa lịch sử scan"""
    scan_history.clear()
    return {"message": "History cleared"}


# ============================================================
# HELPERS
# ============================================================

def _record_scan(result: dict, scan_type: str, start: float):
    """Ghi nhận kết quả scan vào history và stats"""
    result["scan_time"] = round(time.time() - start, 3)

    stats["total_scans"] += 1
    if scan_type == "file":
        stats["files_scanned"] += 1
    elif scan_type == "url":
        stats["urls_scanned"] += 1

    if result.get("detected"):
        stats["threats_detected"] += 1

    # Lưu history (giữ max 500 records)
    entry = {
        "timestamp": datetime.now().isoformat(),
        "type": scan_type,
        "detected": result.get("detected", False),
        "threat_level": result.get("threat_level", "unknown"),
        "method": result.get("method", "unknown"),
        "scan_time": result.get("scan_time", 0),
    }

    if scan_type == "file":
        entry["filename"] = result.get("filename", "unknown")
        entry["file_size"] = result.get("file_size", 0)
    elif scan_type == "url":
        entry["url"] = result.get("url", "")
    elif scan_type == "waf":
        entry["attacks"] = result.get("attacks", [])
        entry["action"] = result.get("action", "")

    scan_history.append(entry)
    if len(scan_history) > 500:
        scan_history.pop(0)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("  HThuong Antivirus AI — API Server")
    print("=" * 50)
    print(f"  Hash DB: {len(hash_engine.hash_set)} hashes loaded")
    print(f"  VirusTotal: {'Connected' if vt_engine else 'Not configured'}")
    print(f"  Heuristic: Active")
    print(f"  WAF: Active")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=8000)
