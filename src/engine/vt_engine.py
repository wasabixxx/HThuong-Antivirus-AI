"""
HThuong Antivirus AI — VirusTotal Integration Engine
Tầng 2: Quét bằng VirusTotal API (70+ antivirus engines)
"""

import hashlib
import os
import time
import json
import requests


class VirusTotalEngine:
    """
    Tích hợp VirusTotal API v3.
    - scan_by_hash(): gửi hash kiểm tra (không upload file, bảo mật)
    - upload_and_scan(): upload file lên VT quét
    - scan_url(): kiểm tra URL phishing/malicious
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}
        self.cache: dict = {}
        self.last_call_time = 0.0

    def _rate_limit(self):
        """Đảm bảo không vượt quá 4 requests/phút (free tier)"""
        elapsed = time.time() - self.last_call_time
        if elapsed < 15:
            time.sleep(15 - elapsed)
        self.last_call_time = time.time()

    def _sha256(self, file_path: str) -> str | None:
        """Tính SHA-256 hash của file"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, PermissionError, OSError):
            return None

    def _sha256_bytes(self, data: bytes) -> str:
        """Tính SHA-256 từ bytes"""
        return hashlib.sha256(data).hexdigest()

    def scan_by_hash(self, file_path: str = None, file_hash: str = None) -> dict:
        """
        Gửi hash lên VirusTotal kiểm tra.
        Không upload file → nhanh, bảo mật, tiết kiệm bandwidth.
        """
        if file_hash is None:
            if file_path is None:
                return {"error": "Need file_path or file_hash"}
            file_hash = self._sha256(file_path)
            if not file_hash:
                return {"error": "Cannot compute hash"}

        # Cache check
        if file_hash in self.cache:
            result = self.cache[file_hash].copy()
            result["from_cache"] = True
            return result

        self._rate_limit()

        url = f"{self.BASE_URL}/files/{file_hash}"
        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = requests.get(url, headers=self.headers, timeout=30)

                if resp.status_code == 429:
                    # Rate limit — exponential backoff
                    wait = 15 * (2 ** attempt)
                    if attempt < max_retries - 1:
                        time.sleep(wait)
                        continue
                    return {"error": "Rate limit exceeded after retries"}

                break  # Thành công hoặc lỗi khác → thoát loop

            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    time.sleep(5 * (attempt + 1))
                    continue
                return {"error": "VirusTotal API timeout after retries"}
            except requests.exceptions.ConnectionError:
                if attempt < max_retries - 1:
                    time.sleep(5 * (attempt + 1))
                    continue
                return {"error": "Cannot connect to VirusTotal after retries"}
            except Exception as e:
                return {"error": f"Unexpected error: {str(e)}"}

        try:
            if resp.status_code == 200:
                data = resp.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})
                results = data.get("last_analysis_results", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)
                total = malicious + suspicious + undetected + harmless

                # Lấy top detections
                detections = []
                for engine_name, r in results.items():
                    if r["category"] in ("malicious", "suspicious"):
                        detections.append({
                            "engine": engine_name,
                            "result": r.get("result", "Unknown"),
                            "category": r["category"],
                        })
                detections.sort(key=lambda x: x["category"])

                # Tên virus phổ biến nhất
                threat_names = [d["result"] for d in detections if d["result"]]
                common_name = max(set(threat_names), key=threat_names.count) if threat_names else None

                result = {
                    "detected": malicious > 0,
                    "method": "virustotal",
                    "hash": file_hash,
                    "stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "undetected": undetected,
                        "harmless": harmless,
                        "total": total,
                    },
                    "confidence": round(malicious / max(total, 1), 3),
                    "threat_level": self._threat_level(malicious, total),
                    "threat_name": common_name,
                    "detections": detections[:15],
                    "vt_link": f"https://www.virustotal.com/gui/file/{file_hash}",
                    "from_cache": False,
                }

                self.cache[file_hash] = result
                return result

            elif resp.status_code == 404:
                return {
                    "detected": False,
                    "method": "virustotal",
                    "hash": file_hash,
                    "message": "Not found in VirusTotal database",
                    "stats": {"malicious": 0, "total": 0},
                    "confidence": 0.0,
                    "threat_level": "unknown",
                }

            elif resp.status_code == 401:
                return {"error": "Invalid API key"}

            else:
                return {"error": f"VirusTotal API error: {resp.status_code}"}

        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    def upload_and_scan(self, file_path: str) -> dict:
        """
        Upload file lên VirusTotal để quét.
        Dùng khi scan_by_hash trả về 404 (file chưa có trên VT).
        ⚠️ File sẽ được lưu trên VT servers.
        """
        file_size = os.path.getsize(file_path)

        self._rate_limit()

        try:
            if file_size <= 32 * 1024 * 1024:
                url = f"{self.BASE_URL}/files"
            else:
                resp = requests.get(
                    f"{self.BASE_URL}/files/upload_url",
                    headers=self.headers,
                    timeout=30,
                )
                url = resp.json()["data"]

            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                resp = requests.post(url, headers=self.headers, files=files, timeout=120)

            if resp.status_code == 200:
                analysis_id = resp.json()["data"]["id"]
                return {
                    "status": "queued",
                    "analysis_id": analysis_id,
                    "message": "File uploaded to VirusTotal. Results will be available shortly.",
                }
            else:
                return {"error": f"Upload failed: {resp.status_code}"}

        except Exception as e:
            return {"error": f"Upload error: {str(e)}"}

    def check_analysis(self, analysis_id: str) -> dict:
        """Kiểm tra kết quả phân tích sau khi upload"""
        self._rate_limit()

        try:
            url = f"{self.BASE_URL}/analyses/{analysis_id}"
            resp = requests.get(url, headers=self.headers, timeout=30)

            if resp.status_code == 200:
                data = resp.json()["data"]["attributes"]
                status = data.get("status")
                if status == "completed":
                    stats = data.get("stats", {})
                    return {
                        "status": "completed",
                        "stats": stats,
                        "detected": stats.get("malicious", 0) > 0,
                    }
                return {"status": "in_progress", "message": "Still scanning..."}

            return {"error": f"API error: {resp.status_code}"}

        except Exception as e:
            return {"error": str(e)}

    def scan_url(self, url_to_scan: str) -> dict:
        """Quét URL bằng VirusTotal"""
        self._rate_limit()

        try:
            # Submit URL
            resp = requests.post(
                f"{self.BASE_URL}/urls",
                headers=self.headers,
                data={"url": url_to_scan},
                timeout=30,
            )

            if resp.status_code != 200:
                return {"error": f"URL submit failed: {resp.status_code}"}

            analysis_id = resp.json()["data"]["id"]

            # Đợi rồi lấy kết quả
            time.sleep(5)
            self._rate_limit()

            result_resp = requests.get(
                f"{self.BASE_URL}/analyses/{analysis_id}",
                headers=self.headers,
                timeout=30,
            )

            if result_resp.status_code == 200:
                data = result_resp.json()["data"]["attributes"]
                stats = data.get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                total = malicious + suspicious + harmless

                return {
                    "url": url_to_scan,
                    "detected": malicious > 0,
                    "method": "virustotal_url",
                    "stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "total": total,
                    },
                    "confidence": round(malicious / max(total, 1), 3),
                    "threat_level": self._threat_level(malicious, total),
                    "vt_link": f"https://www.virustotal.com/gui/url/{analysis_id}",
                }

            return {"error": f"URL analysis error: {result_resp.status_code}"}

        except Exception as e:
            return {"error": f"URL scan error: {str(e)}"}

    def _threat_level(self, malicious: int, total: int) -> str:
        if total == 0:
            return "unknown"
        ratio = malicious / total
        if ratio == 0:
            return "safe"
        elif ratio < 0.1:
            return "low"
        elif ratio < 0.3:
            return "medium"
        elif ratio < 0.6:
            return "high"
        else:
            return "critical"
