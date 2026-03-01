"""
HThuong Antivirus AI — Heuristic Analysis Engine
Tầng 3: Phân tích heuristic offline khi VT không khả dụng
"""

import math
import os


class HeuristicEngine:
    """
    Phát hiện malware bằng phân tích heuristic:
    - Entropy calculation (packed/encrypted detection)
    - Suspicious string patterns
    - File structure analysis
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

    def calculate_entropy(self, data: bytes) -> float:
        """Tính Shannon entropy — malware packed/encrypted thường có entropy > 7.0"""
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        length = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)

        return round(entropy, 4)

    def count_patterns(self, data: bytes, patterns: list[bytes]) -> tuple[int, list[str]]:
        """Đếm số pattern đáng ngờ tìm thấy trong file"""
        lower_data = data.lower()
        found = []
        for p in patterns:
            if p in lower_data:
                found.append(p.decode("ascii", errors="ignore"))
        return len(found), found

    def analyze_pe(self, data: bytes) -> dict:
        """Phân tích PE header cơ bản"""
        info = {"is_pe": False}
        if data[:2] == b"MZ":
            info["is_pe"] = True
            # Kiểm tra packed indicators
            info["has_upx"] = b"UPX" in data[:4096]
            info["has_aspack"] = b"ASPack" in data[:4096]
            info["packed_likely"] = info["has_upx"] or info["has_aspack"]
        return info

    def check(self, file_path: str) -> dict:
        """
        Phân tích heuristic đầy đủ.
        Returns: {detected, method, confidence, threat_level, reasons, analysis}
        """
        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                # Đọc tối đa 2MB để phân tích
                content = f.read(2 * 1024 * 1024)
        except (IOError, PermissionError, OSError):
            return {
                "detected": False,
                "method": "heuristic",
                "error": "Cannot read file",
            }

        score = 0
        reasons = []

        # 1. Entropy check
        entropy = self.calculate_entropy(content)
        if entropy > 7.5:
            score += 35
            reasons.append(f"Very high entropy: {entropy} (likely packed/encrypted)")
        elif entropy > 7.0:
            score += 20
            reasons.append(f"High entropy: {entropy}")

        # 2. Suspicious API/string patterns
        sus_count, sus_found = self.count_patterns(content, self.SUSPICIOUS_PATTERNS)
        if sus_count >= 5:
            score += 35
            reasons.append(f"Many suspicious patterns ({sus_count}): {', '.join(sus_found[:5])}")
        elif sus_count >= 3:
            score += 20
            reasons.append(f"Suspicious patterns ({sus_count}): {', '.join(sus_found[:3])}")
        elif sus_count >= 1:
            score += 10
            reasons.append(f"Some suspicious patterns: {', '.join(sus_found)}")

        # 3. Network activity patterns
        net_count, net_found = self.count_patterns(content, self.NETWORK_PATTERNS)
        if net_count >= 3:
            score += 15
            reasons.append(f"Network activity patterns ({net_count})")

        # 4. PE analysis
        pe_info = self.analyze_pe(content)
        if pe_info.get("packed_likely"):
            score += 20
            reasons.append("Packed executable detected (UPX/ASPack)")

        # 5. Very small or suspicious file size for PE
        if pe_info["is_pe"] and file_size < 10_000:
            score += 10
            reasons.append(f"Suspiciously small PE file ({file_size} bytes)")

        # 6. Null byte ratio (packed files have less null bytes)
        if len(content) > 0:
            null_ratio = content.count(0) / len(content)
            if pe_info["is_pe"] and null_ratio < 0.05:
                score += 10
                reasons.append(f"Low null byte ratio: {null_ratio:.3f}")

        # Determine threat level
        confidence = min(score / 100, 1.0)
        if score >= 60:
            threat_level = "high"
        elif score >= 40:
            threat_level = "medium"
        elif score >= 20:
            threat_level = "low"
        else:
            threat_level = "safe"

        return {
            "detected": score >= 50,
            "method": "heuristic",
            "confidence": round(confidence, 3),
            "threat_level": threat_level,
            "score": score,
            "reasons": reasons,
            "analysis": {
                "entropy": entropy,
                "suspicious_patterns": sus_count,
                "network_patterns": net_count,
                "is_pe": pe_info["is_pe"],
                "packed": pe_info.get("packed_likely", False),
                "file_size": file_size,
            },
        }
