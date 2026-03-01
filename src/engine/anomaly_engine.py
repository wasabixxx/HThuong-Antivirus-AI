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
        Đặc trưng file bình thường:
        - Entropy thấp-trung bình (3.0 - 6.5)
        - Suspicious patterns ít (0-2)
        - Network patterns ít (0-3)
        - Null ratio trung bình (0.05-0.4)
        - Printable ratio cao (0.5-0.95)
        """
        np.random.seed(42)
        n_normal = 500

        # Generate normal file features
        normal_data = np.column_stack([
            np.random.uniform(3.0, 6.5, n_normal),           # entropy
            np.random.lognormal(10, 2, n_normal),             # file_size (log-normal)
            np.random.poisson(0.5, n_normal),                 # suspicious_patterns
            np.random.poisson(1.0, n_normal),                 # network_patterns
            np.random.binomial(1, 0.3, n_normal),             # is_pe
            np.random.uniform(0.05, 0.40, n_normal),          # null_byte_ratio
            np.random.uniform(0.50, 0.95, n_normal),          # printable_ratio
            np.random.uniform(80, 220, n_normal),             # unique_bytes
        ])

        # Thêm một số samples "giống malware" (5%) để model biết anomaly boundary
        n_anomaly = 25
        anomaly_data = np.column_stack([
            np.random.uniform(7.0, 8.0, n_anomaly),          # high entropy
            np.random.lognormal(8, 1, n_anomaly),             # small files
            np.random.poisson(5, n_anomaly),                  # nhiều suspicious patterns
            np.random.poisson(4, n_anomaly),                  # nhiều network patterns
            np.ones(n_anomaly),                               # always PE
            np.random.uniform(0.0, 0.05, n_anomaly),          # low null ratio
            np.random.uniform(0.1, 0.4, n_anomaly),           # low printable ratio
            np.random.uniform(200, 256, n_anomaly),           # high unique bytes
        ])

        training_data = np.vstack([normal_data, anomaly_data])

        self.model.fit(training_data)
        self.is_loaded = True

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
        }
        with open(self.METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2, ensure_ascii=False)

        print(f"[AnomalyEngine] Baseline model trained — {len(training_data)} samples")

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

            is_anomaly = prediction == -1

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
