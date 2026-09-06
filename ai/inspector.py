import math
import re
from typing import Dict, List, Optional, Tuple


class PayloadInspector:
    def __init__(self):
        self.credential_patterns = [
            re.compile(rb'password\s*[:=]', re.IGNORECASE),
            re.compile(rb'passwd\s*[:=]', re.IGNORECASE),
            re.compile(rb'pwd\s*[:=]', re.IGNORECASE),
            re.compile(rb'login\s*[:=]', re.IGNORECASE),
            re.compile(rb'user\s*[:=]', re.IGNORECASE),
            re.compile(rb'authorization:\s*bearer\s+', re.IGNORECASE),
            re.compile(rb'api[_-]?key\s*[:=]', re.IGNORECASE),
            re.compile(rb'secret\s*[:=]', re.IGNORECASE),
            re.compile(rb'token\s*[:=]', re.IGNORECASE),
            re.compile(rb'Basic\s+[A-Za-z0-9+/]{20,}={0,2}', re.IGNORECASE),
        ]

        self.suspicious_patterns = [
            re.compile(rb'cmd\.exe', re.IGNORECASE),
            re.compile(rb'powershell', re.IGNORECASE),
            re.compile(rb'\/bin\/bash', re.IGNORECASE),
            re.compile(rb'\/bin\/sh', re.IGNORECASE),
            re.compile(rb'wget\s+http', re.IGNORECASE),
            re.compile(rb'curl\s+http', re.IGNORECASE),
            re.compile(rb'nc\s+-', re.IGNORECASE),
            re.compile(rb'netcat', re.IGNORECASE),
            re.compile(rb'\.exe', re.IGNORECASE),
            re.compile(rb'\.dll', re.IGNORECASE),
            re.compile(rb'base64', re.IGNORECASE),
        ]

    def inspect(self, flow, payload: Optional[bytes] = None) -> Dict[str, any]:
        result = {
            "has_credentials": False,
            "credential_types": [],
            "has_suspicious_content": False,
            "suspicious_patterns": [],
            "entropy": 0.0,
            "length": 0,
            "encoding": "unknown",
            "risk_score": 0.0,
        }

        if payload is None:
            return result

        result["length"] = len(payload)
        result["entropy"] = self._calculate_entropy(payload)

        result["has_credentials"], result["credential_types"] = self._check_credentials(payload)
        result["has_suspicious_content"], result["suspicious_patterns"] = self._check_suspicious(payload)

        result["encoding"] = self._detect_encoding(payload)

        risk = 0.0
        if result["has_credentials"]:
            risk += 0.5
        if result["has_suspicious_content"]:
            risk += 0.4
        if result["entropy"] > 7.0:
            risk += 0.2
        if len(payload) > 4096:
            risk += 0.1
        result["risk_score"] = min(risk, 1.0)

        return result

    def _check_credentials(self, payload: bytes) -> Tuple[bool, List[str]]:
        found = []
        for pattern in self.credential_patterns:
            if pattern.search(payload):
                found.append(pattern.pattern.decode("utf-8", errors="replace")[:50])
        return bool(found), found

    def _check_suspicious(self, payload: bytes) -> Tuple[bool, List[str]]:
        found = []
        for pattern in self.suspicious_patterns:
            if pattern.search(payload):
                found.append(pattern.pattern.decode("utf-8", errors="replace")[:50])
        return bool(found), found

    def _detect_encoding(self, payload: bytes) -> str:
        if not payload:
            return "empty"
        if self._is_base64(payload):
            return "base64"
        if self._is_hex(payload):
            return "hex"
        try:
            payload.decode("utf-8")
            return "utf-8"
        except UnicodeDecodeError:
            return "binary"

    def _is_base64(self, payload: bytes) -> bool:
        if len(payload) % 4 != 0:
            return False
        try:
            import base64
            base64.b64decode(payload, validate=True)
            return True
        except Exception:
            return False

    def _is_hex(self, payload: bytes) -> bool:
        if len(payload) % 2 != 0:
            return False
        try:
            bytes.fromhex(payload.decode("ascii", errors="replace"))
            return True
        except ValueError:
            return False

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        frequency: Dict[int, int] = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        entropy = 0.0
        length = len(data)
        for count in frequency.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy
