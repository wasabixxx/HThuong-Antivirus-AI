"""
HThuong Antivirus AI — WAF ML Training Script
Huấn luyện mô hình ML cho WAF Engine
Pipeline: TF-IDF (character n-grams) → Random Forest Classifier
Có: GridSearchCV Hyperparameter Tuning + Feature Importance
"""

import os
import sys
import json
import time
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
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
    "max_features": 15000,       # Top 15K features (tăng cho dataset lớn hơn)
    "sublinear_tf": True,        # Dùng log(1 + tf) thay vì raw tf
    "min_df": 2,                 # Bỏ qua n-gram xuất hiện < 2 lần
}

# Random Forest — sẽ được GridSearchCV tune
RF_BASE_PARAMS = {
    "class_weight": "balanced",
    "random_state": 42,
    "n_jobs": -1,
}

# Grid search space
PARAM_GRID = {
    "n_estimators": [100, 200, 300],
    "max_depth": [20, 30, None],
    "min_samples_split": [2, 3, 5],
    "min_samples_leaf": [1, 2],
}


def train(use_grid_search: bool = True):
    """Huấn luyện và lưu mô hình WAF ML"""
    print("=" * 60)
    print("  HThuong Antivirus AI — WAF ML Training")
    print("=" * 60)

    # 1. Load dataset
    print("\n[1/6] Loading dataset (with augmentation)...")
    payloads, labels = get_dataset(augment=True)
    raw_payloads, raw_labels = get_dataset(augment=False)
    print(f"  Raw samples: {len(raw_payloads)}")
    print(f"  Augmented samples: {len(payloads)}")

    from collections import Counter
    counts = Counter(labels)
    for label, count in sorted(counts.items()):
        print(f"  {label}: {count}")

    # 2. Split train/test
    print("\n[2/6] Splitting train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        payloads, labels, test_size=0.2, random_state=42, stratify=labels
    )
    print(f"  Train: {len(X_train)}, Test: {len(X_test)}")

    # 3. TF-IDF Vectorization
    print("\n[3/6] TF-IDF Vectorization (char n-grams)...")
    start = time.time()
    vectorizer = TfidfVectorizer(**TFIDF_PARAMS)
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    print(f"  Feature matrix: {X_train_tfidf.shape}")
    print(f"  Vocabulary size: {len(vectorizer.vocabulary_)}")
    print(f"  Time: {time.time() - start:.2f}s")

    # 4. Train (with optional GridSearchCV)
    if use_grid_search:
        print("\n[4/6] Hyperparameter Tuning (GridSearchCV)...")
        start = time.time()
        base_clf = RandomForestClassifier(**RF_BASE_PARAMS)
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        grid = GridSearchCV(
            base_clf, PARAM_GRID, cv=cv, scoring='accuracy',
            n_jobs=-1, verbose=0, refit=True
        )
        grid.fit(X_train_tfidf, y_train)
        clf = grid.best_estimator_
        train_time = time.time() - start
        best_params = grid.best_params_
        print(f"  Best params: {best_params}")
        print(f"  Best CV score: {grid.best_score_:.4f}")
        print(f"  Total tuning time: {train_time:.2f}s")
    else:
        print("\n[4/6] Training Random Forest (no tuning)...")
        start = time.time()
        clf = RandomForestClassifier(
            n_estimators=200, max_depth=30, min_samples_split=3,
            min_samples_leaf=1, **RF_BASE_PARAMS
        )
        clf.fit(X_train_tfidf, y_train)
        train_time = time.time() - start
        best_params = {"n_estimators": 200, "max_depth": 30, "min_samples_split": 3, "min_samples_leaf": 1}
        print(f"  Training time: {train_time:.2f}s")

    # 5. Evaluate
    print("\n[5/6] Evaluating model...")

    # Train accuracy
    train_acc = clf.score(X_train_tfidf, y_train)
    print(f"\n  Train Accuracy: {train_acc:.4f}")

    # Test accuracy
    test_acc = clf.score(X_test_tfidf, y_test)
    print(f"  Test Accuracy:  {test_acc:.4f}")

    # Cross-validation on full data
    print("\n  Cross-validation (5-fold on full dataset)...")
    X_all_tfidf = vectorizer.transform(payloads)
    cv_scores = cross_val_score(clf, X_all_tfidf, labels, cv=5, scoring='accuracy')
    print(f"  CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Classification report
    y_pred = clf.predict(X_test_tfidf)
    print("\n  Classification Report:")
    report_text = classification_report(y_test, y_pred, digits=4)
    print(report_text)
    report_dict = classification_report(y_test, y_pred, digits=4, output_dict=True)

    # Confusion matrix
    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred, labels=clf.classes_)
    print(f"  Labels: {list(clf.classes_)}")
    for i, row in enumerate(cm):
        print(f"  {clf.classes_[i]:>16s}: {row}")

    # 6. Feature Importance
    print("\n[6/6] Feature Importance Analysis...")
    feature_names = vectorizer.get_feature_names_out()
    importances = clf.feature_importances_
    top_k = 30
    top_indices = np.argsort(importances)[-top_k:][::-1]
    top_features = []
    print(f"\n  Top {top_k} most important n-gram features:")
    for rank, idx in enumerate(top_indices, 1):
        feat = {
            "rank": rank,
            "feature": feature_names[idx],
            "importance": round(float(importances[idx]), 6),
        }
        top_features.append(feat)
        print(f"  {rank:3d}. '{feature_names[idx]}' = {importances[idx]:.6f}")

    # Per-class feature importance (mean TF-IDF per class)
    print("\n  Per-class discriminative features:")
    class_features = {}
    for cls in clf.classes_:
        cls_mask = np.array(y_train) == cls
        cls_tfidf = X_train_tfidf[cls_mask].mean(axis=0).A1
        top_cls = np.argsort(cls_tfidf)[-10:][::-1]
        features = [{"feature": feature_names[i], "mean_tfidf": round(float(cls_tfidf[i]), 4)} for i in top_cls]
        class_features[cls] = features
        print(f"  {cls}: {', '.join(f['feature'].strip() for f in features[:5])}")

    # === Save model ===
    print("\n  Saving model...")
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)

    # Save metadata (comprehensive)
    metadata = {
        "model_type": "RandomForestClassifier",
        "vectorizer_type": "TfidfVectorizer (char_wb n-grams)",
        "tfidf_params": TFIDF_PARAMS,
        "best_params": best_params,
        "hyperparameter_tuned": use_grid_search,
        "classes": list(clf.classes_),
        "dataset": {
            "raw_samples": len(raw_payloads),
            "augmented_samples": len(payloads),
            "augmentation": "URL-encode, double URL-encode, case-swap (SQLi), whitespace padding",
        },
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "train_accuracy": round(train_acc, 4),
        "test_accuracy": round(test_acc, 4),
        "cv_accuracy_mean": round(cv_scores.mean(), 4),
        "cv_accuracy_std": round(cv_scores.std(), 4),
        "cv_folds": 5,
        "per_class_metrics": {k: v for k, v in report_dict.items() if k in clf.classes_},
        "feature_count": X_train_tfidf.shape[1],
        "vocabulary_size": len(vectorizer.vocabulary_),
        "training_time_seconds": round(train_time, 2),
        "top_features": top_features,
        "class_discriminative_features": class_features,
        "confusion_matrix": {
            "labels": list(clf.classes_),
            "matrix": cm.tolist(),
        },
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"\n  Model saved to: {MODEL_PATH}")
    print(f"  Vectorizer saved to: {VECTORIZER_PATH}")
    print(f"  Metadata saved to: {METADATA_PATH}")

    print("\n" + "=" * 60)
    print(f"  DONE! Test Accuracy: {test_acc:.4f}")
    print(f"  Dataset: {len(raw_payloads)} raw → {len(payloads)} augmented")
    if use_grid_search:
        print(f"  Best params: {best_params}")
    print("=" * 60)

    return clf, vectorizer, metadata


if __name__ == "__main__":
    train(use_grid_search=True)
