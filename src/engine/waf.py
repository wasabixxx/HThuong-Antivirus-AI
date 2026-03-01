"""
HThuong Antivirus AI — Web Application Firewall
Phát hiện SQL Injection, XSS, Command Injection
"""

import re


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

    def _check_patterns(self, payload: str, patterns: list[str], attack_type: str) -> dict:
        """Kiểm tra payload với danh sách regex patterns"""
        matched = []
        for pattern in patterns:
            try:
                if re.search(pattern, payload, re.IGNORECASE):
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

        regex_detected = sqli["detected"] or xss["detected"] or cmdi["detected"] or path["detected"]

        attacks_found = []
        if sqli["detected"]:
            attacks_found.append("SQL Injection")
        if xss["detected"]:
            attacks_found.append("XSS")
        if cmdi["detected"]:
            attacks_found.append("Command Injection")
        if path["detected"]:
            attacks_found.append("Path Traversal")

        # === ML Prediction (hybrid layer) ===
        ml_result = None
        if ml_engine and ml_engine.is_loaded:
            ml_result = ml_engine.predict(payload)

            # Hybrid logic:
            # - ML bổ sung nếu regex không phát hiện
            # - ML xác nhận nếu regex đã phát hiện
            if ml_result["is_attack"] and not regex_detected:
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
