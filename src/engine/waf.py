"""
HThuong Antivirus AI — Web Application Firewall
Phát hiện SQL Injection, XSS, Command Injection
Hỗ trợ URL-decode + HTML entity decode để phát hiện payload obfuscated.
"""

import re
import html
from urllib.parse import unquote


class WAFEngine:
    """
    Rule-based + pattern matching WAF engine.
    Phát hiện các dạng tấn công web phổ biến.
    """

    SQLI_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"union.*select",
        r"select.*from",
        r"insert.*into",
        r"delete.*from",
        r"drop\s+(table|database)",
        r"update.*set",
        r"exec(\s|\+)+(s|x)p",
        r"(;|\s)(exec|execute|sp_executesql)",
        r"1\s*=\s*1",
        r"or\s+1\s*=\s*1",
        r"'\s*or\s+'",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"waitfor\s+delay",
        r"having\s+1\s*=\s*1",
        r"group\s+by.*having",
        r"load_file\s*\(",
        r"into\s+(out|dump)file",
    ]

    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"</script>",
        r"javascript\s*:",
        r"vbscript\s*:",
        r"on(error|load|click|mouse|focus|blur|change|submit|key)\s*=",
        r"<img[^>]+src[^>]*=",
        r"<iframe",
        r"<object",
        r"<embed",
        r"<svg[^>]*on",
        r"alert\s*\(",
        r"confirm\s*\(",
        r"prompt\s*\(",
        r"document\.(cookie|write|location)",
        r"window\.(location|open)",
        r"eval\s*\(",
        r"expression\s*\(",
        r"url\s*\(",
        r"<\s*body[^>]*onload",
        r"&#[x]?[0-9a-f]+",
        r"\\x[0-9a-f]{2}",
    ]

    CMDI_PATTERNS = [
        r";\s*(ls|cat|whoami|id|uname|pwd|dir)",
        r"\|\s*(ls|cat|whoami|id|uname|pwd|dir)",
        r"`[^`]*`",
        r"\$\([^)]*\)",
        r"&&\s*(ls|cat|whoami|id|rm|del|net)",
        r"\|\|\s*(ls|cat|whoami)",
        r">\s*/",
        r";\s*rm\s",
        r";\s*wget\s",
        r";\s*curl\s",
        r";\s*nc\s",
        r";\s*bash\s",
        r";\s*sh\s",
        r";\s*python",
        r";\s*perl",
        r";\s*php",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e[/\\]",
        r"%252e%252e",
        r"/etc/passwd",
        r"/etc/shadow",
        r"c:\\windows",
        r"c:\\boot\.ini",
    ]
    SSRF_PATTERNS = [
        # Internal IP ranges
        r"https?://127\.0\.0\.1",
        r"https?://localhost",
        r"https?://0\.0\.0\.0",
        r"https?://10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        r"https?://172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"https?://192\.168\.",
        r"https?://169\.254\.",        # AWS metadata link-local
        r"https?://\[::1\]",            # IPv6 localhost
        # Cloud metadata endpoints
        r"https?://169\.254\.169\.254",  # AWS/GCP metadata
        r"https?://metadata\.google\.internal",
        r"/latest/meta-data",
        r"/metadata/v1",
        # Schemes
        r"gopher://",
        r"file:///",
        r"dict://",
        r"ftp://127\.",
        r"ftp://localhost",
        # DNS rebinding / bypass
        r"https?://0x7f",               # Hex IP 127.x
        r"https?://2130706433",          # Decimal 127.0.0.1
        r"https?://017700000001",         # Octal 127.0.0.1
    ]
    def check_sqli(self, payload: str) -> dict:
        """Kiểm tra SQL Injection"""
        return self._check_patterns(payload, self.SQLI_PATTERNS, "sqli")

    def check_xss(self, payload: str) -> dict:
        """Kiểm tra Cross-Site Scripting"""
        return self._check_patterns(payload, self.XSS_PATTERNS, "xss")

    def check_cmdi(self, payload: str) -> dict:
        """Kiểm tra Command Injection"""
        return self._check_patterns(payload, self.CMDI_PATTERNS, "command_injection")

    def check_path_traversal(self, payload: str) -> dict:
        """Kiểm tra Path Traversal"""
        return self._check_patterns(payload, self.PATH_TRAVERSAL_PATTERNS, "path_traversal")

    def check_ssrf(self, payload: str) -> dict:
        """Kiểm tra Server-Side Request Forgery"""
        return self._check_patterns(payload, self.SSRF_PATTERNS, "ssrf")

    @staticmethod
    def _normalize_payload(payload: str) -> str:
        """
        Chuẩn hóa payload trước khi kiểm tra regex:
        1. URL-decode (double decode để xử lý %252e → %2e → .)
        2. HTML entity decode (&#x3C; → <, &lt; → <)
        3. Loại bỏ null bytes
        Giúp phát hiện payload obfuscated bypass WAF.
        """
        # Double URL-decode
        decoded = unquote(unquote(payload))
        # HTML entity decode
        decoded = html.unescape(decoded)
        # Loại bỏ null bytes (thường dùng để bypass WAF)
        decoded = decoded.replace("\x00", "")
        return decoded

    def _check_patterns(self, payload: str, patterns: list[str], attack_type: str) -> dict:
        """Kiểm tra payload với danh sách regex patterns (sau khi normalize)"""
        # Normalize payload (URL-decode, HTML entity decode)
        normalized = self._normalize_payload(payload)

        matched = []
        for pattern in patterns:
            try:
                # Kiểm tra cả payload gốc và payload đã normalize
                if re.search(pattern, payload, re.IGNORECASE) or \
                   re.search(pattern, normalized, re.IGNORECASE):
                    matched.append(pattern)
            except re.error:
                continue

        detected = len(matched) > 0
        confidence = min(len(matched) * 0.25, 1.0)

        return {
            "detected": detected,
            "attack_type": attack_type,
            "confidence": round(confidence, 3),
            "matched_rules": len(matched),
            "severity": self._severity(len(matched)),
        }

    def check_all(self, payload: str, ml_engine=None) -> dict:
        """Kiểm tra tất cả các dạng tấn công (hybrid: regex + ML)"""
        sqli = self.check_sqli(payload)
        xss = self.check_xss(payload)
        cmdi = self.check_cmdi(payload)
        path = self.check_path_traversal(payload)
        ssrf = self.check_ssrf(payload)

        regex_detected = sqli["detected"] or xss["detected"] or cmdi["detected"] or path["detected"] or ssrf["detected"]

        # Tổng số rules match (dùng để đánh giá regex confidence)
        total_regex_matches = (
            sqli["matched_rules"] + xss["matched_rules"]
            + cmdi["matched_rules"] + path["matched_rules"]
            + ssrf["matched_rules"]
        )

        regex_attacks_found = []
        if sqli["detected"]:
            regex_attacks_found.append("SQL Injection")
        if xss["detected"]:
            regex_attacks_found.append("XSS")
        if cmdi["detected"]:
            regex_attacks_found.append("Command Injection")
        if path["detected"]:
            regex_attacks_found.append("Path Traversal")
        if ssrf["detected"]:
            regex_attacks_found.append("SSRF")

        attacks_found = list(regex_attacks_found)  # copy

        # === ML Prediction (hybrid layer) ===
        ml_result = None
        if ml_engine and ml_engine.is_loaded:
            ml_result = ml_engine.predict(payload)

            # ===== HYBRID DECISION LOGIC =====
            #
            # Case 1: Regex detected + ML says safe → ML override nếu:
            #   - Regex chỉ match ≤ 2 rule (low confidence)
            #   - ML confidence safe >= 0.7
            #   → Tin ML, bỏ qua regex false positive
            #
            # Case 2: Regex detected + ML cũng detected
            #   → Cả hai đồng ý block. Dùng ML classification (chính xác hơn).
            #
            # Case 3: Regex clean + ML detected → ML bổ sung nếu confidence >= 0.7
            #
            # Case 4: Cả hai clean → safe
            #

            if regex_detected and not ml_result["is_attack"]:
                # ML nói safe — kiểm tra xem regex có đang false positive không
                if total_regex_matches <= 2 and ml_result["confidence"] >= 0.7:
                    # Regex match ít rule, ML tự tin nói safe → override
                    regex_detected = False
                    attacks_found = []
                    ml_result["ml_override"] = True

            elif regex_detected and ml_result["is_attack"]:
                # Cả hai phát hiện → dùng ML classification vì chính xác hơn (~98%)
                # Giữ lại SSRF từ regex vì ML không được train trên SSRF
                ssrf_preserved = "SSRF" in regex_attacks_found
                attacks_found = [ml_result["predicted_name"]]
                if ssrf_preserved and "SSRF" not in attacks_found:
                    attacks_found.append("SSRF")
                ml_result["ml_classification_used"] = True

            elif not regex_detected and ml_result["is_attack"]:
                # Regex không thấy, ML phát hiện → bổ sung
                if ml_result["confidence"] >= 0.7:
                    attacks_found.append(f"{ml_result['predicted_name']} (ML)")

        any_detected = regex_detected or (
            ml_result is not None
            and ml_result["is_attack"]
            and ml_result["confidence"] >= 0.7
        )

        result = {
            "payload": payload[:200],
            "detected": any_detected,
            "action": "BLOCKED" if any_detected else "ALLOWED",
            "method": "waf",
            "detection_method": "hybrid" if ml_result else "regex_only",
            "attacks": attacks_found,
            "details": {
                "sqli": sqli,
                "xss": xss,
                "command_injection": cmdi,
                "path_traversal": path,
                "ssrf": ssrf,
            },
        }

        # Thêm ML analysis vào result
        if ml_result:
            result["ml_analysis"] = ml_result

        return result

    def _severity(self, matched_count: int) -> str:
        if matched_count >= 4:
            return "critical"
        elif matched_count >= 2:
            return "high"
        elif matched_count >= 1:
            return "medium"
        return "safe"
