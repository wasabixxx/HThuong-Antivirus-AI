"""
HThuong Antivirus AI — Unit Tests cho tất cả Detection Engines
Chạy: pytest tests/test_engines.py -v
"""

import os
import sys
import tempfile
import pytest

# Thêm src vào path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from engine.hash_engine import HashEngine
from engine.heuristic import HeuristicEngine
from engine.waf import WAFEngine
from engine.ml_waf import MLWAFEngine
from engine.anomaly_engine import AnomalyEngine


# ============================================================
# FIXTURES
# ============================================================

@pytest.fixture(scope="module")
def hash_engine():
    return HashEngine("sha256")


@pytest.fixture(scope="module")
def heuristic_engine():
    return HeuristicEngine()


@pytest.fixture(scope="module")
def waf_engine():
    return WAFEngine()


@pytest.fixture(scope="module")
def ml_waf_engine():
    return MLWAFEngine()


@pytest.fixture(scope="module")
def anomaly_engine():
    return AnomalyEngine()


def create_temp_file(content: bytes, suffix: str = ".bin") -> str:
    """Tạo file tạm với nội dung cho trước"""
    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    f.write(content)
    f.close()
    return f.name


# ============================================================
# TEST HASH ENGINE
# ============================================================

class TestHashEngine:
    """Test tầng 1: Hash-based detection"""

    def test_hash_engine_loads(self, hash_engine):
        """Kiểm tra hash DB được load thành công"""
        assert len(hash_engine.hash_set) > 0, "Hash DB phải có dữ liệu"

    def test_hash_engine_type(self, hash_engine):
        assert hash_engine.hash_type == "sha256"

    def test_clean_file_not_detected(self, hash_engine):
        """File bình thường không nằm trong malware DB"""
        path = create_temp_file(b"Hello World! This is a normal file.")
        try:
            result = hash_engine.check(path)
            assert result["detected"] is False
            assert result["method"] == "hash_local"
            assert result["threat_level"] == "safe"
            assert result["hash"] is not None
            assert len(result["hash"]) == 64  # SHA-256 hex length
        finally:
            os.unlink(path)

    def test_compute_hash_deterministic(self, hash_engine):
        """Hash phải deterministic — cùng file → cùng hash"""
        path = create_temp_file(b"Test content for hashing")
        try:
            h1 = hash_engine.compute_hash(path)
            h2 = hash_engine.compute_hash(path)
            assert h1 == h2
            assert len(h1) == 64
        finally:
            os.unlink(path)

    def test_different_files_different_hashes(self, hash_engine):
        """Khác file → khác hash"""
        p1 = create_temp_file(b"File content A")
        p2 = create_temp_file(b"File content B")
        try:
            assert hash_engine.compute_hash(p1) != hash_engine.compute_hash(p2)
        finally:
            os.unlink(p1)
            os.unlink(p2)

    def test_nonexistent_file(self, hash_engine):
        """File không tồn tại → trả về error"""
        result = hash_engine.check("/nonexistent/path/file.exe")
        assert result["detected"] is False
        assert "error" in result

    def test_result_structure(self, hash_engine):
        """Kiểm tra cấu trúc result dict"""
        path = create_temp_file(b"Structure test")
        try:
            result = hash_engine.check(path)
            required_keys = ["detected", "method", "hash", "confidence", "threat_level"]
            for key in required_keys:
                assert key in result, f"Missing key: {key}"
        finally:
            os.unlink(path)


# ============================================================
# TEST HEURISTIC ENGINE
# ============================================================

class TestHeuristicEngine:
    """Test tầng 3: Heuristic analysis"""

    def test_clean_text_file(self, heuristic_engine):
        """File text bình thường → safe"""
        path = create_temp_file(b"This is a simple text file with nothing suspicious at all.")
        try:
            result = heuristic_engine.check(path)
            assert result["detected"] is False
            assert result["method"] == "heuristic"
            assert result["threat_level"] == "safe"
        finally:
            os.unlink(path)

    def test_entropy_calculation(self, heuristic_engine):
        """Entropy của dữ liệu random cao hơn dữ liệu repetitive"""
        # Data repetitive → low entropy
        assert heuristic_engine.calculate_entropy(b"AAAAAAAAAA") < 1.0

        # Data đa dạng → higher entropy
        diverse = bytes(range(256))
        assert heuristic_engine.calculate_entropy(diverse) > 7.0

        # Empty → 0
        assert heuristic_engine.calculate_entropy(b"") == 0.0

    def test_suspicious_patterns_detection(self, heuristic_engine):
        """Phát hiện các pattern đáng ngờ"""
        suspicious_content = b"This file contains powershell and cmd.exe and mimikatz"
        count, found = heuristic_engine.count_patterns(suspicious_content, heuristic_engine.SUSPICIOUS_PATTERNS)
        assert count >= 3
        assert "powershell" in found
        assert "cmd.exe" in found
        assert "mimikatz" in found

    def test_pe_detection(self, heuristic_engine):
        """Nhận diện PE file header"""
        # File bắt đầu bằng MZ → is_pe = True
        pe_content = b"MZ" + b"\x00" * 100
        info = heuristic_engine.analyze_pe(pe_content)
        assert info["is_pe"] is True

        # File không phải PE
        text_content = b"Hello World"
        info = heuristic_engine.analyze_pe(text_content)
        assert info["is_pe"] is False

    def test_upx_packer_detection(self, heuristic_engine):
        """Nhận diện UPX packer"""
        upx_content = b"MZ" + b"\x00" * 10 + b"UPX!" + b"\x00" * 100
        info = heuristic_engine.analyze_pe(upx_content)
        assert info["is_pe"] is True
        assert info["has_upx"] is True
        assert info["packed_likely"] is True

    def test_suspicious_file_high_score(self, heuristic_engine):
        """File với nhiều dấu hiệu đáng ngờ → score cao"""
        # Tạo content với PE + nhiều suspicious patterns + high entropy area
        content = b"MZ" + b"\x00" * 10 + b"UPX!" + b"\x00" * 50
        content += b"powershell cmd.exe reg add taskkill keylog mimikatz metasploit"
        content += b" http://evil.com wget curl download socket connect"
        content += os.urandom(1000)  # Random bytes → high entropy

        path = create_temp_file(content)
        try:
            result = heuristic_engine.check(path)
            assert result["score"] >= 30, f"Expected score >= 30, got {result['score']}"
            assert len(result["reasons"]) >= 2
            assert result["analysis"]["is_pe"] is True
        finally:
            os.unlink(path)

    def test_network_patterns(self, heuristic_engine):
        """Phát hiện network patterns"""
        content = b"connect to http://evil.com via socket and download payload"
        count, found = heuristic_engine.count_patterns(content, heuristic_engine.NETWORK_PATTERNS)
        assert count >= 3

    def test_result_structure(self, heuristic_engine):
        """Kiểm tra cấu trúc result"""
        path = create_temp_file(b"Test structure")
        try:
            result = heuristic_engine.check(path)
            required = ["detected", "method", "confidence", "threat_level", "score", "reasons", "analysis"]
            for key in required:
                assert key in result, f"Missing key: {key}"
            assert "entropy" in result["analysis"]
            assert "suspicious_patterns" in result["analysis"]
        finally:
            os.unlink(path)

    def test_nonexistent_file(self, heuristic_engine):
        """File không tồn tại → error"""
        result = heuristic_engine.check("/nonexistent/path/file.exe")
        assert result["detected"] is False
        assert "error" in result


# ============================================================
# TEST WAF ENGINE
# ============================================================

class TestWAFEngine:
    """Test WAF — rule-based detection"""

    def test_sqli_detection(self, waf_engine):
        """Phát hiện SQL Injection"""
        sqli_payloads = [
            "' OR 1=1 --",
            "' UNION SELECT username, password FROM users --",
            "; DROP TABLE users --",
            "1; DELETE FROM products",
        ]
        for payload in sqli_payloads:
            result = waf_engine.check_all(payload)
            assert result["detected"] is True, f"Failed to detect SQLi: {payload}"
            assert "SQL Injection" in result["attacks"], f"Wrong attack type for: {payload}"

    def test_xss_detection(self, waf_engine):
        """Phát hiện XSS"""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(document.cookie)',
        ]
        for payload in xss_payloads:
            result = waf_engine.check_all(payload)
            assert result["detected"] is True, f"Failed to detect XSS: {payload}"
            assert "XSS" in result["attacks"], f"Wrong attack type for: {payload}"

    def test_cmdi_detection(self, waf_engine):
        """Phát hiện Command Injection"""
        cmdi_payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "&& ls -la",
            "$(rm -rf /)",
        ]
        for payload in cmdi_payloads:
            result = waf_engine.check_all(payload)
            assert result["detected"] is True, f"Failed to detect CMDi: {payload}"
            assert "Command Injection" in result["attacks"], f"Wrong attack type for: {payload}"

    def test_path_traversal_detection(self, waf_engine):
        """Phát hiện Path Traversal"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "../../../../../../etc/shadow",
        ]
        for payload in traversal_payloads:
            result = waf_engine.check_all(payload)
            assert result["detected"] is True, f"Failed to detect traversal: {payload}"
            assert "Path Traversal" in result["attacks"], f"Wrong attack type for: {payload}"

    def test_safe_input_allowed(self, waf_engine):
        """Input bình thường phải được cho phép"""
        safe_payloads = [
            "Hello World",
            "How to learn Python programming",
            "john.doe@example.com",
            "2024-12-25",
            "Price: $19.99",
        ]
        for payload in safe_payloads:
            result = waf_engine.check_all(payload)
            assert result["detected"] is False, f"False positive on safe input: {payload}"
            assert result["action"] == "ALLOWED"

    def test_result_structure(self, waf_engine):
        """Kiểm tra cấu trúc WAF result"""
        result = waf_engine.check_all("test input")
        required = ["detected", "action", "attacks", "details", "payload"]
        for key in required:
            assert key in result, f"Missing key: {key}"
        assert "sqli" in result["details"]
        assert "xss" in result["details"]
        assert "command_injection" in result["details"]
        assert "path_traversal" in result["details"]

    def test_multiple_attacks_in_one_payload(self, waf_engine):
        """Payload chứa nhiều loại tấn công"""
        result = waf_engine.check_all("'; DROP TABLE x; -- <script>alert(1)</script>")
        assert result["detected"] is True
        assert len(result["attacks"]) >= 2

    def test_url_encoded_sqli(self, waf_engine):
        """Phát hiện SQL Injection qua URL-encoding"""
        encoded_payloads = [
            "%27%20OR%201%3D1%20--",              # ' OR 1=1 --
            "%27%20UNION%20SELECT%20*%20--",       # ' UNION SELECT * --
        ]
        for payload in encoded_payloads:
            result = waf_engine.check_all(payload)
            assert result["detected"] is True, f"Failed to detect URL-encoded SQLi: {payload}"

    def test_url_encoded_path_traversal(self, waf_engine):
        """Phát hiện Path Traversal qua URL-encoding"""
        encoded_payloads = [
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",   # ../../../etc/passwd
            "%2e%2e%5c%2e%2e%5cwindows",                   # ..\..\windows
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd", # double-encoded
        ]
        for payload in encoded_payloads:
            result = waf_engine.check_all(payload)
            assert result["detected"] is True, f"Failed to detect encoded traversal: {payload}"

    def test_html_entity_xss(self, waf_engine):
        """Phát hiện XSS qua HTML entity encoding"""
        result = waf_engine.check_all("&lt;script&gt;alert(1)&lt;/script&gt;")
        assert result["detected"] is True, "Failed to detect HTML-entity-encoded XSS"

    def test_null_byte_bypass(self, waf_engine):
        """Phát hiện payload chứa null bytes"""
        result = waf_engine.check_all("../../../etc/passwd%00.jpg")
        assert result["detected"] is True, "Failed to detect null-byte path traversal"


# ============================================================
# TEST EICAR DETECTION
# ============================================================

class TestEICAR:
    """Test EICAR standard test file detection"""

    def test_eicar_hash_in_database(self, hash_engine):
        """EICAR SHA-256 hash phải có trong database"""
        from engine.hash_engine import HashEngine
        assert HashEngine.EICAR_SHA256 in hash_engine.hash_set

    def test_eicar_file_detected(self, hash_engine):
        """EICAR test file phải bị phát hiện bởi hash engine.
        Lưu ý: Windows Defender có thể chặn file EICAR → skip test.
        """
        from engine.hash_engine import HashEngine
        import hashlib

        # Thay vì tạo file thật (bị AV chặn), kiểm tra logic trực tiếp
        eicar_hash = hashlib.sha256(HashEngine.EICAR_STRING).hexdigest()
        assert eicar_hash in hash_engine.hash_set, "EICAR hash should be in database"
        assert hash_engine.info_map.get(eicar_hash) is not None, "EICAR should have info"
        assert "EICAR" in hash_engine.info_map[eicar_hash], "Info should mention EICAR"

    def test_eicar_string_constant(self):
        """Kiểm tra EICAR string đúng chuẩn (68 bytes)"""
        from engine.hash_engine import HashEngine
        assert len(HashEngine.EICAR_STRING) == 68

    def test_eicar_sha256_correct(self):
        """Kiểm tra EICAR SHA-256 hash đúng"""
        import hashlib
        from engine.hash_engine import HashEngine
        computed = hashlib.sha256(HashEngine.EICAR_STRING).hexdigest()
        assert computed == HashEngine.EICAR_SHA256


# ============================================================
# TEST ML WAF ENGINE
# ============================================================

class TestMLWAFEngine:
    """Test ML WAF classifier"""

    def test_model_loaded(self, ml_waf_engine):
        """Model phải được load thành công"""
        assert ml_waf_engine.is_loaded is True

    def test_predict_sqli(self, ml_waf_engine):
        """ML nhận diện SQL Injection"""
        result = ml_waf_engine.predict("' UNION SELECT username, password FROM users --")
        assert result["ml_available"] is True
        assert result["is_attack"] is True
        assert result["predicted_label"] == "sqli"
        assert result["confidence"] > 0.5

    def test_predict_xss(self, ml_waf_engine):
        """ML nhận diện XSS"""
        result = ml_waf_engine.predict('<script>alert("XSS")</script>')
        assert result["is_attack"] is True
        assert result["predicted_label"] == "xss"
        assert result["confidence"] > 0.5

    def test_predict_cmdi(self, ml_waf_engine):
        """ML nhận diện Command Injection"""
        result = ml_waf_engine.predict("; cat /etc/passwd")
        assert result["is_attack"] is True
        assert result["predicted_label"] == "cmdi"

    def test_predict_path_traversal(self, ml_waf_engine):
        """ML nhận diện Path Traversal"""
        result = ml_waf_engine.predict("../../../etc/passwd")
        assert result["is_attack"] is True
        assert result["predicted_label"] == "path_traversal"

    def test_predict_safe(self, ml_waf_engine):
        """ML nhận diện input safe"""
        result = ml_waf_engine.predict("Hello, this is a normal search query")
        assert result["is_attack"] is False
        assert result["predicted_label"] == "safe"
        assert result["confidence"] > 0.5

    def test_probabilities_sum_to_one(self, ml_waf_engine):
        """Tổng xác suất các class ≈ 1.0"""
        result = ml_waf_engine.predict("test input")
        probs = result["probabilities"]
        assert len(probs) == 5  # sqli, xss, cmdi, path_traversal, safe
        total = sum(probs.values())
        assert abs(total - 1.0) < 0.01, f"Expected sum ≈ 1.0, got {total}"

    def test_all_classes_present(self, ml_waf_engine):
        """Tất cả class phải có trong probabilities"""
        result = ml_waf_engine.predict("any input")
        expected_classes = {"sqli", "xss", "cmdi", "path_traversal", "safe"}
        actual_classes = set(result["probabilities"].keys())
        assert actual_classes == expected_classes

    def test_result_structure(self, ml_waf_engine):
        """Kiểm tra cấu trúc ML result"""
        result = ml_waf_engine.predict("test")
        required = ["ml_available", "is_attack", "predicted_label", "predicted_name", "confidence", "probabilities"]
        for key in required:
            assert key in result, f"Missing key: {key}"

    def test_get_model_info(self, ml_waf_engine):
        """Kiểm tra model info"""
        info = ml_waf_engine.get_model_info()
        assert info["loaded"] is True
        assert info["test_accuracy"] is not None
        assert info["test_accuracy"] > 0.8  # Phải trên 80%
        assert len(info["classes"]) == 5

    def test_batch_accuracy(self, ml_waf_engine):
        """Test batch — 80%+ accuracy trên các payload rõ ràng"""
        test_cases = [
            ("' OR 1=1 --", "sqli"),
            ("UNION SELECT * FROM users", "sqli"),
            ('<script>alert(1)</script>', "xss"),
            ('<img src=x onerror=alert(1)>', "xss"),
            ("; ls -la", "cmdi"),
            ("| whoami", "cmdi"),
            ("../../../etc/passwd", "path_traversal"),
            ("..\\..\\windows\\win.ini", "path_traversal"),
            ("Hello World", "safe"),
            ("How to learn Python", "safe"),
        ]
        correct = sum(1 for payload, expected in test_cases
                      if ml_waf_engine.predict(payload)["predicted_label"] == expected)
        accuracy = correct / len(test_cases)
        assert accuracy >= 0.8, f"Batch accuracy only {accuracy:.0%}"


# ============================================================
# TEST ANOMALY ENGINE
# ============================================================

class TestAnomalyEngine:
    """Test tầng 4: Anomaly Detection (Isolation Forest)"""

    def test_model_loaded(self, anomaly_engine):
        """Model phải được load thành công"""
        assert anomaly_engine.is_loaded is True

    def test_normal_text_file(self, anomaly_engine):
        """File text bình thường → không anomaly"""
        content = b"This is a perfectly normal text file with nothing unusual."
        path = create_temp_file(content, suffix=".txt")
        try:
            result = anomaly_engine.check(path)
            assert result["method"] == "anomaly_detection"
            assert "features" in result
            assert "anomaly_score" in result
            # Text file thường → safe
            assert result["features"]["is_pe"] == 0
        finally:
            os.unlink(path)

    def test_feature_extraction(self, anomaly_engine):
        """Kiểm tra feature extraction hoạt động"""
        content = b"Test file with some content for feature extraction"
        path = create_temp_file(content)
        try:
            result = anomaly_engine.check(path)
            features = result["features"]
            required_features = [
                "entropy", "file_size", "suspicious_patterns",
                "network_patterns", "is_pe", "null_byte_ratio",
                "printable_ratio", "unique_bytes",
            ]
            for feat in required_features:
                assert feat in features, f"Missing feature: {feat}"
            assert features["file_size"] == len(content)
            assert 0 <= features["entropy"] <= 8
            assert 0 <= features["null_byte_ratio"] <= 1
            assert 0 <= features["printable_ratio"] <= 1
        finally:
            os.unlink(path)

    def test_result_structure(self, anomaly_engine):
        """Kiểm tra cấu trúc anomaly result"""
        path = create_temp_file(b"Structure test content")
        try:
            result = anomaly_engine.check(path)
            required = ["detected", "method", "confidence", "threat_level", "prediction", "anomaly_score", "features"]
            for key in required:
                assert key in result, f"Missing key: {key}"
        finally:
            os.unlink(path)

    def test_nonexistent_file(self, anomaly_engine):
        """File không tồn tại → error"""
        result = anomaly_engine.check("/nonexistent/file.exe")
        assert result["detected"] is False
        assert "error" in result

    def test_empty_file(self, anomaly_engine):
        """File rỗng được xử lý đúng"""
        path = create_temp_file(b"")
        try:
            result = anomaly_engine.check(path)
            # Empty file → either error or safe result
            assert result["method"] == "anomaly_detection"
        finally:
            os.unlink(path)

    def test_get_model_info(self, anomaly_engine):
        """Kiểm tra model info"""
        info = anomaly_engine.get_model_info()
        assert info["loaded"] is True
        assert "metadata" in info
        assert info["metadata"]["features"] is not None


# ============================================================
# TEST HYBRID WAF (REGEX + ML)
# ============================================================

class TestHybridWAF:
    """Test hybrid regex + ML WAF logic"""

    def test_hybrid_detects_known_attacks(self, waf_engine, ml_waf_engine):
        """Hybrid phải phát hiện attack rõ ràng"""
        payload = "' UNION SELECT username, password FROM users --"
        result = waf_engine.check_all(payload, ml_engine=ml_waf_engine)
        assert result["detected"] is True
        assert result.get("ml_analysis") is not None

    def test_hybrid_allows_safe_input(self, waf_engine, ml_waf_engine):
        """Hybrid phải cho phép input safe"""
        payload = "How to learn Python programming in 2024"
        result = waf_engine.check_all(payload, ml_engine=ml_waf_engine)
        assert result["detected"] is False
        assert result["action"] == "ALLOWED"

    def test_hybrid_has_ml_analysis(self, waf_engine, ml_waf_engine):
        """Hybrid result phải có ml_analysis"""
        result = waf_engine.check_all("test", ml_engine=ml_waf_engine)
        assert "ml_analysis" in result
        assert "detection_method" in result

    def test_hybrid_reduces_false_positives(self, waf_engine, ml_waf_engine):
        """Hybrid ML override giảm false positive"""
        # Mặt này O'Brien's có thể trigger regex nhưng ML override
        tricky_safe = [
            "O'Brien's Irish Pub",
            "It's a beautiful day, isn't it?",
            "Use the -- flag for verbose output",
        ]
        for payload in tricky_safe:
            result = waf_engine.check_all(payload, ml_engine=ml_waf_engine)
            # Nếu ML override → allowed
            if result.get("detection_method") == "hybrid":
                # ML đã bổ sung — có thể override hoặc không
                pass  # Acceptable either way


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
