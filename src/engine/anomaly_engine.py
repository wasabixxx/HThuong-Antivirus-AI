"""
HThuong Antivirus AI — Anomaly Detection Engine
Sử dụng Isolation Forest (unsupervised ML) để phát hiện file bất thường.
Không cần label — học từ đặc trưng của file bình thường.
"""

import os
import math
import json
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class AnomalyEngine:
    """
    Anomaly Detection Engine dùng Isolation Forest.
    Extract features từ file → predict anomaly score.
    Features: entropy, file_size, suspicious_patterns, network_patterns,
              is_pe, null_byte_ratio, printable_ratio, unique_bytes.
    """

    SUSPICIOUS_PATTERNS = [
        b"cmd.exe", b"powershell", b"reg add", b"taskkill",
        b"createremotethread", b"virtualallocex", b"writeprocessmemory",
        b"urldownloadtofile", b"winexec", b"shellexecute",
        b"keylog", b"screenshot", b"password", b"bitcoin",
        b"ransom", b"encrypt", b"decrypt", b"mimikatz",
        b"metasploit", b"payload", b"reverse_tcp", b"bind_shell",
    ]

    NETWORK_PATTERNS = [
        b"http://", b"https://", b"ftp://", b"socket",
        b"connect", b"send(", b"recv(", b"urllib",
        b"wget", b"curl", b"download",
    ]

    MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "models", "anomaly")
    MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
    METADATA_PATH = os.path.join(MODEL_DIR, "anomaly_metadata.json")

    # Ngưỡng confidence tối thiểu để flag anomaly
    # Tránh false positive cho file hợp lệ có anomaly score thấp
    MIN_CONFIDENCE_THRESHOLD = 0.55

    def __init__(self):
        self.model = None
        self.is_loaded = False
        self.metadata = None
        self._load_or_create_model()

    def _load_or_create_model(self):
        """Load model nếu có, nếu chưa thì tạo mới với default params"""
        if not ML_AVAILABLE:
            print("[AnomalyEngine] scikit-learn not installed — disabled")
            return

        if os.path.exists(self.MODEL_PATH):
            try:
                self.model = joblib.load(self.MODEL_PATH)
                if os.path.exists(self.METADATA_PATH):
                    with open(self.METADATA_PATH, "r", encoding="utf-8") as f:
                        self.metadata = json.load(f)
                self.is_loaded = True
                print(f"[AnomalyEngine] Model loaded — samples: {self.metadata.get('trained_samples', 'N/A')}")
                return
            except Exception as e:
                print(f"[AnomalyEngine] Failed to load: {e}")

        # Tạo model mới với pre-configured params
        # contamination: tỉ lệ anomaly giả định (5%)
        self.model = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            max_features=1.0,
            random_state=42,
            n_jobs=-1,
        )

        # Train trên synthetic "normal" data để có baseline
        self._train_baseline()

    def _train_baseline(self):
        """
        Huấn luyện baseline model trên synthetic normal file features.
        Bao gồm nhiều nhóm file bình thường thực tế:
        
        Nhóm 1 — Văn bản, script, config (entropy thấp):
          Entropy 2.5-5.5, printable cao, ít suspicious patterns
        
        Nhóm 2 — PE executable hợp lệ (entropy trung bình-cao):
          Entropy 5.5-7.8, nhiều unique bytes (230-256), 
          có network/suspicious patterns vì phần mềm hợp lệ chứa cmd.exe, http://, encrypt...
        
        Nhóm 3 — File nén, installer, media (entropy cao):
          Entropy 7.0-7.99, file lớn, printable ratio thấp
        
        Nhóm anomaly — File thực sự đáng ngờ:
          Kết hợp entropy cao + RẤT NHIỀU suspicious patterns + file nhỏ bất thường
        """
        np.random.seed(42)

        # === Nhóm 1: Văn bản, script, config, source code ===
        n_text = 200
        text_data = np.column_stack([
            np.random.uniform(2.5, 5.5, n_text),             # entropy thấp (text)
            np.random.lognormal(9, 2, n_text),                # file_size đa dạng
            np.random.poisson(0.3, n_text),                   # rất ít suspicious
            np.random.poisson(0.8, n_text),                   # ít network patterns
            np.zeros(n_text),                                 # không phải PE
            np.random.uniform(0.01, 0.15, n_text),           # ít null bytes
            np.random.uniform(0.65, 0.98, n_text),           # printable ratio cao
            np.random.uniform(60, 180, n_text),              # unique bytes trung bình
        ])

        # === Nhóm 2: PE executable hợp lệ (phần mềm từ hãng lớn) ===
        # Ví dụ: Chrome, Office, driver, system tools...
        # Có entropy cao do nén, nhiều strings chứa http, cmd, encrypt...
        n_pe = 250
        pe_data = np.column_stack([
            np.random.uniform(5.5, 7.8, n_pe),               # entropy cao (compressed sections)
            np.random.lognormal(12, 2.5, n_pe),              # file size lớn (MB range)
            np.random.poisson(3.0, n_pe),                    # có suspicious patterns (bình thường cho software)
            np.random.poisson(4.0, n_pe),                    # nhiều network patterns (http, connect, socket)
            np.ones(n_pe),                                   # là PE file
            np.random.uniform(0.05, 0.50, n_pe),             # null byte ratio đa dạng
            np.random.uniform(0.15, 0.65, n_pe),             # printable ratio thấp hơn (binary)
            np.random.uniform(200, 256, n_pe),               # gần đủ 256 unique bytes
        ])

        # === Nhóm 3: File nén, installer, media, database ===
        n_compressed = 150
        compressed_data = np.column_stack([
            np.random.uniform(7.0, 7.99, n_compressed),      # entropy rất cao (nén)
            np.random.lognormal(13, 2, n_compressed),         # file size lớn
            np.random.poisson(1.0, n_compressed),             # ít suspicious (dữ liệu nén)
            np.random.poisson(1.5, n_compressed),             # ít network
            np.random.binomial(1, 0.2, n_compressed),         # ít khi là PE
            np.random.uniform(0.00, 0.15, n_compressed),      # ít null bytes
            np.random.uniform(0.05, 0.35, n_compressed),      # printable ratio rất thấp
            np.random.uniform(230, 256, n_compressed),        # gần đủ unique bytes
        ])

        # === Nhóm 4: DLL, system files ===
        n_dll = 100
        dll_data = np.column_stack([
            np.random.uniform(5.0, 7.5, n_dll),              # entropy trung bình-cao
            np.random.lognormal(11, 2, n_dll),                # file size đa dạng
            np.random.poisson(2.0, n_dll),                    # một số suspicious patterns
            np.random.poisson(2.5, n_dll),                    # một số network patterns
            np.ones(n_dll),                                   # luôn là PE
            np.random.uniform(0.10, 0.50, n_dll),             # null byte ratio
            np.random.uniform(0.20, 0.70, n_dll),             # printable ratio
            np.random.uniform(180, 256, n_dll),               # nhiều unique bytes
        ])

        # === Nhóm anomaly: File thực sự đáng ngờ ===
        # Đặc trưng: file NHỎ + entropy cao + RẤT NHIỀU suspicious + nhiều network
        # Đây là dấu hiệu malware dropper, payload, backdoor
        n_anomaly = 40
        anomaly_data = np.column_stack([
            np.random.uniform(6.5, 8.0, n_anomaly),          # entropy cao
            np.random.lognormal(7, 1.5, n_anomaly),           # file NHỎ (dropper/payload ~KB)
            np.random.poisson(8, n_anomaly),                  # RẤT NHIỀU suspicious patterns (>8)
            np.random.poisson(6, n_anomaly),                  # nhiều network patterns
            np.random.binomial(1, 0.7, n_anomaly),            # thường là PE
            np.random.uniform(0.0, 0.08, n_anomaly),          # null ratio rất thấp
            np.random.uniform(0.10, 0.45, n_anomaly),         # printable ratio thấp
            np.random.uniform(150, 256, n_anomaly),           # unique bytes
        ])

        normal_data = np.vstack([text_data, pe_data, compressed_data, dll_data])
        training_data = np.vstack([normal_data, anomaly_data])

        self.model.fit(training_data)
        self.is_loaded = True

        n_normal = len(normal_data)
        # Save
        os.makedirs(self.MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, self.MODEL_PATH)

        self.metadata = {
            "model_type": "IsolationForest",
            "trained_samples": len(training_data),
            "normal_samples": n_normal,
            "anomaly_samples": n_anomaly,
            "contamination": 0.05,
            "n_estimators": 150,
            "features": [
                "entropy", "file_size", "suspicious_patterns", "network_patterns",
                "is_pe", "null_byte_ratio", "printable_ratio", "unique_bytes"
            ],
            "normal_groups": {
                "text_script_config": n_text,
                "pe_executable": n_pe,
                "compressed_media": n_compressed,
                "dll_system": n_dll,
            },
        }
        with open(self.METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2, ensure_ascii=False)

        print(f"[AnomalyEngine] Baseline model trained — {len(training_data)} samples ({n_normal} normal + {n_anomaly} anomaly)")

    def extract_features(self, file_path: str) -> np.ndarray | None:
        """Extract feature vector từ file"""
        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                content = f.read(2 * 1024 * 1024)  # Max 2MB
        except (IOError, PermissionError, OSError):
            return None

        # 1. Shannon Entropy
        if len(content) > 0:
            byte_counts = [0] * 256
            for b in content:
                byte_counts[b] += 1
            length = len(content)
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    prob = count / length
                    entropy -= prob * math.log2(prob)
        else:
            entropy = 0.0

        # 2. Suspicious pattern count
        lower_content = content.lower()
        sus_count = sum(1 for p in self.SUSPICIOUS_PATTERNS if p in lower_content)

        # 3. Network pattern count
        net_count = sum(1 for p in self.NETWORK_PATTERNS if p in lower_content)

        # 4. Is PE?
        is_pe = 1 if content[:2] == b"MZ" else 0

        # 5. Null byte ratio
        null_ratio = content.count(0) / len(content) if len(content) > 0 else 0

        # 6. Printable ratio (ASCII 32-126)
        printable = sum(1 for b in content if 32 <= b <= 126)
        printable_ratio = printable / len(content) if len(content) > 0 else 0

        # 7. Unique bytes
        unique_bytes = len(set(content))

        features = np.array([
            entropy,
            file_size,
            sus_count,
            net_count,
            is_pe,
            null_ratio,
            printable_ratio,
            unique_bytes,
        ]).reshape(1, -1)

        return features

    def check(self, file_path: str) -> dict:
        """
        Phân tích anomaly cho file.
        Returns: {detected, method, anomaly_score, confidence, features, ...}
        """
        if not self.is_loaded:
            return {
                "detected": False,
                "method": "anomaly_detection",
                "ml_available": False,
                "error": "Model not loaded",
            }

        features = self.extract_features(file_path)
        if features is None:
            return {
                "detected": False,
                "method": "anomaly_detection",
                "error": "Cannot read file",
            }

        try:
            # Isolation Forest: -1 = anomaly, 1 = normal
            prediction = self.model.predict(features)[0]

            # Anomaly score: giá trị càng âm = càng bất thường
            # decision_function trả về score, càng âm càng anomaly
            raw_score = self.model.decision_function(features)[0]

            # Normalize score thành confidence (0.0 - 1.0)
            # raw_score < 0 → anomaly, raw_score > 0 → normal
            # Map: -0.5 → 1.0 (rất đáng ngờ), +0.5 → 0.0 (rất bình thường)
            confidence = max(0.0, min(1.0, 0.5 - float(raw_score)))

            is_anomaly = bool(prediction == -1)

            # Chỉ flag là detected khi confidence đủ cao
            # Tránh false positive: file hợp lệ thường có anomaly score gần ranh giới
            # nhưng confidence thấp → không nên cảnh báo
            if is_anomaly and confidence < self.MIN_CONFIDENCE_THRESHOLD:
                is_anomaly = False

            # Determine threat level
            if confidence >= 0.7:
                threat_level = "high"
            elif confidence >= 0.5:
                threat_level = "medium"
            elif confidence >= 0.3:
                threat_level = "low"
            else:
                threat_level = "safe"

            feature_names = [
                "entropy", "file_size", "suspicious_patterns", "network_patterns",
                "is_pe", "null_byte_ratio", "printable_ratio", "unique_bytes"
            ]
            feature_dict = {name: round(float(val), 4) for name, val in zip(feature_names, features[0])}

            return {
                "detected": is_anomaly,
                "method": "anomaly_detection",
                "ml_available": True,
                "anomaly_score": round(float(raw_score), 4),
                "confidence": round(confidence, 4),
                "threat_level": threat_level if is_anomaly else "safe",
                "prediction": "anomaly" if is_anomaly else "normal",
                "features": feature_dict,
            }

        except Exception as e:
            return {
                "detected": False,
                "method": "anomaly_detection",
                "error": str(e),
            }

    def get_model_info(self) -> dict:
        """Thông tin model"""
        if not self.is_loaded:
            return {"loaded": False}
        return {
            "loaded": True,
            "model_type": "IsolationForest",
            "metadata": self.metadata,
        }
