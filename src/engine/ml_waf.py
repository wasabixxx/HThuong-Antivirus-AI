"""
HThuong Antivirus AI — ML-powered WAF Engine
Sử dụng TF-IDF + Random Forest để phân loại tấn công web.
Kết hợp với rule-based WAF để tạo hệ thống hybrid.
"""

import os
import json
import numpy as np

try:
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class MLWAFEngine:
    """
    Machine Learning WAF Engine.
    Dùng TF-IDF vectorizer + Random Forest classifier.
    Cho phép predict loại tấn công và confidence score.
    """

    # Mapping nhãn ML → tên hiển thị
    LABEL_DISPLAY = {
        "sqli": "SQL Injection",
        "xss": "Cross-Site Scripting (XSS)",
        "cmdi": "Command Injection",
        "path_traversal": "Path Traversal",
        "safe": "Safe",
    }

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.metadata = None
        self.is_loaded = False
        self._load_model()

    def _load_model(self):
        """Load pre-trained model và vectorizer"""
        if not ML_AVAILABLE:
            print("[MLWAFEngine] scikit-learn/joblib not installed — ML WAF disabled")
            return

        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_dir = os.path.join(base_dir, "..", "..", "models", "waf")

        model_path = os.path.join(model_dir, "waf_rf_model.joblib")
        vectorizer_path = os.path.join(model_dir, "waf_tfidf_vectorizer.joblib")
        metadata_path = os.path.join(model_dir, "waf_model_metadata.json")

        if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
            print("[MLWAFEngine] Model not found — run train_waf_model.py first")
            return

        try:
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)

            if os.path.exists(metadata_path):
                with open(metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            self.is_loaded = True
            accuracy = self.metadata.get("test_accuracy", "N/A") if self.metadata else "N/A"
            print(f"[MLWAFEngine] Model loaded — accuracy: {accuracy}")

        except Exception as e:
            print(f"[MLWAFEngine] Failed to load model: {e}")
            self.model = None
            self.vectorizer = None

    def predict(self, payload: str) -> dict:
        """
        Dự đoán loại tấn công từ payload.
        Returns: {
            predicted_label, predicted_name, confidence,
            is_attack, probabilities, ml_available
        }
        """
        if not self.is_loaded:
            return {
                "ml_available": False,
                "is_attack": False,
                "predicted_label": None,
                "predicted_name": None,
                "confidence": 0.0,
                "probabilities": {},
            }

        try:
            # Vectorize payload
            X = self.vectorizer.transform([payload])

            # Predict class
            predicted_label = self.model.predict(X)[0]

            # Predict probabilities
            proba = self.model.predict_proba(X)[0]
            classes = self.model.classes_

            # Build probability dict
            probabilities = {}
            for cls, prob in zip(classes, proba):
                probabilities[cls] = round(float(prob), 4)

            # Max confidence
            confidence = float(max(proba))
            is_attack = predicted_label != "safe"

            return {
                "ml_available": True,
                "is_attack": is_attack,
                "predicted_label": predicted_label,
                "predicted_name": self.LABEL_DISPLAY.get(predicted_label, predicted_label),
                "confidence": round(confidence, 4),
                "probabilities": probabilities,
            }

        except Exception as e:
            return {
                "ml_available": True,
                "is_attack": False,
                "predicted_label": "error",
                "predicted_name": f"Error: {str(e)}",
                "confidence": 0.0,
                "probabilities": {},
            }

    def get_model_info(self) -> dict:
        """Trả về thông tin mô hình"""
        if not self.is_loaded:
            return {
                "loaded": False,
                "reason": "Model not loaded" if ML_AVAILABLE else "scikit-learn not installed",
            }

        return {
            "loaded": True,
            "model_type": self.metadata.get("model_type", "Unknown") if self.metadata else "Unknown",
            "test_accuracy": self.metadata.get("test_accuracy") if self.metadata else None,
            "cv_accuracy": self.metadata.get("cv_accuracy_mean") if self.metadata else None,
            "feature_count": self.metadata.get("feature_count") if self.metadata else None,
            "train_samples": self.metadata.get("train_samples") if self.metadata else None,
            "trained_at": self.metadata.get("trained_at") if self.metadata else None,
            "classes": list(self.model.classes_) if self.model else [],
        }
