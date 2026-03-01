"""
HThuong Antivirus AI — WAF ML Training Script
Huấn luyện mô hình ML cho WAF Engine
Pipeline: TF-IDF (character n-grams) → Random Forest Classifier
"""

import os
import sys
import json
import time
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Import dataset
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from waf_dataset import get_dataset

# ============================================================
# CONFIG
# ============================================================

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "models", "waf")
MODEL_PATH = os.path.join(MODEL_DIR, "waf_rf_model.joblib")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "waf_tfidf_vectorizer.joblib")
METADATA_PATH = os.path.join(MODEL_DIR, "waf_model_metadata.json")

# TF-IDF params
TFIDF_PARAMS = {
    "analyzer": "char_wb",       # Character n-grams với word boundaries
    "ngram_range": (2, 5),       # 2-grams đến 5-grams
    "max_features": 10000,       # Top 10K features
    "sublinear_tf": True,        # Dùng log(1 + tf) thay vì raw tf
    "min_df": 2,                 # Bỏ qua n-gram xuất hiện < 2 lần
}

# Random Forest params
RF_PARAMS = {
    "n_estimators": 200,         # 200 cây
    "max_depth": 30,             # Độ sâu tối đa
    "min_samples_split": 3,      # Min samples để split node
    "min_samples_leaf": 1,
    "class_weight": "balanced",  # Cân bằng class weight
    "random_state": 42,
    "n_jobs": -1,                # Dùng tất cả CPU cores
}


def train():
    """Huấn luyện và lưu mô hình WAF ML"""
    print("=" * 60)
    print("  HThuong Antivirus AI — WAF ML Training")
    print("=" * 60)

    # 1. Load dataset
    print("\n[1/5] Loading dataset...")
    payloads, labels = get_dataset()
    print(f"  Total samples: {len(payloads)}")

    from collections import Counter
    counts = Counter(labels)
    for label, count in sorted(counts.items()):
        print(f"  {label}: {count}")

    # 2. Split train/test
    print("\n[2/5] Splitting train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        payloads, labels, test_size=0.2, random_state=42, stratify=labels
    )
    print(f"  Train: {len(X_train)}, Test: {len(X_test)}")

    # 3. TF-IDF Vectorization
    print("\n[3/5] TF-IDF Vectorization (char n-grams)...")
    start = time.time()
    vectorizer = TfidfVectorizer(**TFIDF_PARAMS)
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    print(f"  Feature matrix: {X_train_tfidf.shape}")
    print(f"  Vocabulary size: {len(vectorizer.vocabulary_)}")
    print(f"  Time: {time.time() - start:.2f}s")

    # 4. Train Random Forest
    print("\n[4/5] Training Random Forest...")
    start = time.time()
    clf = RandomForestClassifier(**RF_PARAMS)
    clf.fit(X_train_tfidf, y_train)
    train_time = time.time() - start
    print(f"  Training time: {train_time:.2f}s")

    # 5. Evaluate
    print("\n[5/5] Evaluating model...")

    # Train accuracy
    train_acc = clf.score(X_train_tfidf, y_train)
    print(f"\n  Train Accuracy: {train_acc:.4f}")

    # Test accuracy
    test_acc = clf.score(X_test_tfidf, y_test)
    print(f"  Test Accuracy:  {test_acc:.4f}")

    # Cross-validation
    print("\n  Cross-validation (5-fold)...")
    X_all_tfidf = vectorizer.transform(payloads)
    cv_scores = cross_val_score(clf, X_all_tfidf, labels, cv=5, scoring='accuracy')
    print(f"  CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Classification report
    y_pred = clf.predict(X_test_tfidf)
    print("\n  Classification Report:")
    report = classification_report(y_test, y_pred, digits=4)
    print(report)

    # Confusion matrix
    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred, labels=clf.classes_)
    print(f"  Labels: {list(clf.classes_)}")
    for i, row in enumerate(cm):
        print(f"  {clf.classes_[i]:>16s}: {row}")

    # 6. Save model
    print("\n  Saving model...")
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)

    # Save metadata
    metadata = {
        "model_type": "RandomForestClassifier",
        "vectorizer_type": "TfidfVectorizer (char_wb n-grams)",
        "tfidf_params": TFIDF_PARAMS,
        "rf_params": {k: v for k, v in RF_PARAMS.items() if k != "n_jobs"},
        "classes": list(clf.classes_),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "train_accuracy": round(train_acc, 4),
        "test_accuracy": round(test_acc, 4),
        "cv_accuracy_mean": round(cv_scores.mean(), 4),
        "cv_accuracy_std": round(cv_scores.std(), 4),
        "feature_count": X_train_tfidf.shape[1],
        "vocabulary_size": len(vectorizer.vocabulary_),
        "training_time_seconds": round(train_time, 2),
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"\n  Model saved to: {MODEL_PATH}")
    print(f"  Vectorizer saved to: {VECTORIZER_PATH}")
    print(f"  Metadata saved to: {METADATA_PATH}")

    print("\n" + "=" * 60)
    print(f"  DONE! Test Accuracy: {test_acc:.4f}")
    print("=" * 60)

    return clf, vectorizer, metadata


if __name__ == "__main__":
    train()
