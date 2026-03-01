"""Quick script to find regex false positives on safe payloads"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from engine.waf import WAFEngine
from engine.waf_dataset import SAFE_PAYLOADS

waf = WAFEngine()
fp_count = 0
for p in SAFE_PAYLOADS:
    r = waf.check_all(p)
    if r["detected"]:
        fp_count += 1
        attacks = r["attacks"]
        details = []
        for key in ("sqli", "xss", "command_injection", "path_traversal"):
            d = r["details"][key]
            if d["detected"]:
                details.append(f"{key}(rules={d['matched_rules']})")
        print(f"FP: {p[:70]:<72} => {', '.join(details)}")
print(f"\nTotal false positives: {fp_count}/{len(SAFE_PAYLOADS)}")
