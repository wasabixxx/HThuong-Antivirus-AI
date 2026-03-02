"""
HThuong Antivirus AI — Hash-based Detection Engine
Tầng 1: Quét offline siêu nhanh bằng local hash database
"""

import hashlib
import logging
import os

logger = logging.getLogger("hthuong.hash_engine")


class HashEngine:
    """
    Phát hiện malware dựa trên SHA-256/MD5 hash signature.
    Lookup O(1) bằng Python set().
    Tích hợp EICAR test file hash cho demo/testing.
    """

    # EICAR Standard Anti-Virus Test File
    # https://www.eicar.org/download-anti-malware-testfile/
    EICAR_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"

    def __init__(self, hash_type: str = "sha256"):
        self.hash_type = hash_type.lower()
        self.hash_set: set = set()
        self.info_map: dict = {}
        self._load_database()
        self._add_eicar()

    def _load_database(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_base = os.path.join(base_dir, "..", "database", "HashDataBase")

        if self.hash_type == "sha256":
            hash_path = os.path.join(db_base, "HashDataBase", "Sha256", "virusHash.unibit")
            info_path = os.path.join(db_base, "HashDataBase", "Sha256", "virusInfo.unibit")
        elif self.hash_type == "md5":
            hash_path = os.path.join(db_base, "HashDataBase", "Md5", "md5HashOfVirus.unibit")
            info_path = None
        else:
            raise ValueError(f"Unsupported hash type: {self.hash_type}")

        # Load hashes
        if os.path.exists(hash_path):
            with open(hash_path, "r") as f:
                hashes = [line.strip().lower() for line in f if line.strip()]

            # Load info (nếu có)
            infos = []
            if info_path and os.path.exists(info_path):
                with open(info_path, "r") as f:
                    infos = [line.strip() for line in f if line.strip()]

            for i, h in enumerate(hashes):
                self.hash_set.add(h)
                if i < len(infos):
                    self.info_map[h] = infos[i]

        logger.info(f"Loaded {len(self.hash_set)} {self.hash_type} hashes")

    def _add_eicar(self):
        """Thêm EICAR test file hash vào database — dùng cho demo/testing"""
        if self.hash_type == "sha256":
            self.hash_set.add(self.EICAR_SHA256)
            self.info_map[self.EICAR_SHA256] = "EICAR-Test-File (NOT a virus)"
        elif self.hash_type == "md5":
            self.hash_set.add(self.EICAR_MD5)
            self.info_map[self.EICAR_MD5] = "EICAR-Test-File (NOT a virus)"

    def compute_hash(self, file_path: str) -> str | None:
        """Tính hash của file"""
        try:
            h = hashlib.sha256() if self.hash_type == "sha256" else hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, PermissionError, OSError):
            return None

    def check(self, file_path: str) -> dict:
        """
        Kiểm tra file có trong local hash DB không.
        Returns: {detected, method, hash, confidence, threat_name}
        """
        file_hash = self.compute_hash(file_path)
        if not file_hash:
            return {
                "detected": False,
                "method": "hash_local",
                "error": "Cannot read file",
            }

        is_malware = file_hash in self.hash_set
        return {
            "detected": is_malware,
            "method": "hash_local",
            "hash": file_hash,
            "confidence": 1.0 if is_malware else 0.0,
            "threat_level": "critical" if is_malware else "safe",
            "threat_name": self.info_map.get(file_hash, "Known Malware") if is_malware else None,
        }
