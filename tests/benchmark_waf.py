"""
HThuong Antivirus AI — WAF Benchmark & Metrics
So sánh Regex-only vs ML-only vs Hybrid WAF
Tạo confusion matrix, precision, recall, F1 cho báo cáo luận văn.
"""

import os
import sys
import time
import json
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from engine.waf import WAFEngine
from engine.ml_waf import MLWAFEngine
from engine.waf_dataset import get_dataset

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support,
)


def regex_predict(waf: WAFEngine, payload: str) -> str:
    """Dự đoán bằng regex WAF → trả về label"""
    result = waf.check_all(payload)
    if not result["detected"]:
        return "safe"

    attacks = result["attacks"]
    # Ưu tiên trả về loại đầu tiên
    for attack in attacks:
        if "SQL" in attack:
            return "sqli"
        if "XSS" in attack:
            return "xss"
        if "Command" in attack:
            return "cmdi"
        if "Path" in attack:
            return "path_traversal"
    return "safe"


def ml_predict(ml_engine: MLWAFEngine, payload: str) -> str:
    """Dự đoán bằng ML WAF"""
    result = ml_engine.predict(payload)
    return result["predicted_label"] or "safe"


def hybrid_predict(waf: WAFEngine, ml_engine: MLWAFEngine, payload: str) -> str:
    """Dự đoán hybrid: regex + ML.
    Khi cả regex và ML đều phát hiện attack → dùng ML classification
    vì ML chính xác hơn (~98%) ở việc phân loại TYPE tấn công.
    """
    result = waf.check_all(payload, ml_engine=ml_engine)

    if not result["detected"]:
        return "safe"

    ml_result = result.get("ml_analysis", {})

    # Kiểm tra regex có phát hiện không
    regex_detected = any([
        result["details"]["sqli"]["detected"],
        result["details"]["xss"]["detected"],
        result["details"]["command_injection"]["detected"],
        result["details"]["path_traversal"]["detected"],
    ])

    # Khi cả regex + ML đồng ý attack → tin ML classification (chính xác hơn)
    if regex_detected and ml_result.get("is_attack"):
        return ml_result.get("predicted_label", "safe")

    # Chỉ regex phát hiện (ML bị override vì ko đủ confident) → dùng regex
    if regex_detected:
        if result["details"]["sqli"]["detected"]:
            return "sqli"
        if result["details"]["xss"]["detected"]:
            return "xss"
        if result["details"]["command_injection"]["detected"]:
            return "cmdi"
        if result["details"]["path_traversal"]["detected"]:
            return "path_traversal"

    # Chỉ ML phát hiện → dùng ML label
    if ml_result.get("is_attack"):
        return ml_result.get("predicted_label", "safe")

    return "safe"


def run_benchmark():
    """Chạy benchmark so sánh 3 phương pháp"""
    print("=" * 70)
    print("  HThuong Antivirus AI — WAF Benchmark")
    print("  So sánh: Regex-only vs ML-only vs Hybrid")
    print("=" * 70)

    # Load engines
    print("\n[1] Loading engines...")
    waf = WAFEngine()
    ml_waf = MLWAFEngine()

    if not ml_waf.is_loaded:
        print("ERROR: ML WAF model not loaded. Run train_waf_model.py first.")
        return

    # Load dataset
    print("[2] Loading dataset...")
    payloads, labels = get_dataset()
    print(f"  Total: {len(payloads)} samples")

    # Dùng toàn bộ dataset để benchmark (cả train+test)
    label_names = sorted(set(labels))

    # ============================================================
    # BENCHMARK 3 METHODS
    # ============================================================
    methods = {
        "Regex-only": lambda p: regex_predict(waf, p),
        "ML-only": lambda p: ml_predict(ml_waf, p),
        "Hybrid (Regex+ML)": lambda p: hybrid_predict(waf, ml_waf, p),
    }

    results = {}

    for method_name, predict_fn in methods.items():
        print(f"\n{'='*70}")
        print(f"  {method_name}")
        print(f"{'='*70}")

        start = time.time()
        predictions = [predict_fn(p) for p in payloads]
        elapsed = time.time() - start

        # Metrics
        acc = accuracy_score(labels, predictions)
        precision, recall, f1, support = precision_recall_fscore_support(
            labels, predictions, labels=label_names, average=None, zero_division=0
        )

        print(f"\n  Accuracy: {acc:.4f}")
        print(f"  Time: {elapsed:.3f}s ({len(payloads)/elapsed:.0f} payloads/sec)")

        print(f"\n  {'Class':<18} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
        print(f"  {'-'*58}")
        for i, label in enumerate(label_names):
            print(f"  {label:<18} {precision[i]:>10.4f} {recall[i]:>10.4f} {f1[i]:>10.4f} {support[i]:>10}")

        # Macro / Weighted avg
        p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
            labels, predictions, average="macro", zero_division=0
        )
        p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(
            labels, predictions, average="weighted", zero_division=0
        )
        print(f"  {'-'*58}")
        print(f"  {'macro avg':<18} {p_macro:>10.4f} {r_macro:>10.4f} {f1_macro:>10.4f} {len(labels):>10}")
        print(f"  {'weighted avg':<18} {p_weighted:>10.4f} {r_weighted:>10.4f} {f1_weighted:>10.4f} {len(labels):>10}")

        # Confusion matrix
        cm = confusion_matrix(labels, predictions, labels=label_names)
        print(f"\n  Confusion Matrix:")
        print(f"  {'':>18}", end="")
        for label in label_names:
            print(f" {label[:8]:>8}", end="")
        print()

        for i, row in enumerate(cm):
            print(f"  {label_names[i]:>18}", end="")
            for val in row:
                print(f" {val:>8}", end="")
            print()

        # Binary metrics (attack vs safe)
        binary_true = ["attack" if l != "safe" else "safe" for l in labels]
        binary_pred = ["attack" if p != "safe" else "safe" for p in predictions]
        binary_acc = accuracy_score(binary_true, binary_pred)
        b_p, b_r, b_f1, _ = precision_recall_fscore_support(
            binary_true, binary_pred, labels=["attack", "safe"], average=None, zero_division=0
        )
        print(f"\n  Binary (Attack vs Safe):")
        print(f"  Detection Rate (Recall-attack): {b_r[0]:.4f}")
        print(f"  False Positive Rate:            {1 - b_r[1]:.4f}")
        print(f"  Binary Accuracy:                {binary_acc:.4f}")

        results[method_name] = {
            "accuracy": round(acc, 4),
            "macro_f1": round(f1_macro, 4),
            "weighted_f1": round(f1_weighted, 4),
            "detection_rate": round(float(b_r[0]), 4),
            "false_positive_rate": round(float(1 - b_r[1]), 4),
            "time_seconds": round(elapsed, 3),
            "payloads_per_sec": round(len(payloads) / elapsed, 0),
        }

    # ============================================================
    # COMPARE TABLE
    # ============================================================
    print(f"\n\n{'='*70}")
    print("  COMPARISON SUMMARY")
    print(f"{'='*70}")
    print(f"\n  {'Metric':<28} {'Regex':>12} {'ML':>12} {'Hybrid':>12}")
    print(f"  {'-'*64}")

    metrics_to_show = [
        ("Accuracy", "accuracy"),
        ("Macro F1", "macro_f1"),
        ("Weighted F1", "weighted_f1"),
        ("Detection Rate", "detection_rate"),
        ("False Positive Rate", "false_positive_rate"),
        ("Speed (payloads/sec)", "payloads_per_sec"),
    ]

    for display_name, key in metrics_to_show:
        vals = [results[m][key] for m in methods]
        fmt = ".4f" if key != "payloads_per_sec" else ".0f"
        print(f"  {display_name:<28} {vals[0]:>12{fmt}} {vals[1]:>12{fmt}} {vals[2]:>12{fmt}}")

    # Best method
    best = max(results, key=lambda m: results[m]["weighted_f1"])
    print(f"\n  Best overall (Weighted F1): {best} ({results[best]['weighted_f1']:.4f})")

    # Save results
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "waf")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "benchmark_results.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved to: {output_path}")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmark()
