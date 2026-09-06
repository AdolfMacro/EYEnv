import math
import re
from typing import Dict, List, Optional


class FeatureExtractor:
    def __init__(self):
        self.credential_patterns = [
            re.compile(rb'password', re.IGNORECASE),
            re.compile(rb'passwd', re.IGNORECASE),
            re.compile(rb'login', re.IGNORECASE),
            re.compile(rb'authorization', re.IGNORECASE),
            re.compile(rb'bearer', re.IGNORECASE),
            re.compile(rb'token', re.IGNORECASE),
            re.compile(rb'api_key', re.IGNORECASE),
            re.compile(rb'secret', re.IGNORECASE),
        ]

    def extract(self, flow) -> Dict:
        features = {
            "packet_size": self._safe_int(getattr(flow, "size", 0)),
            "protocol": self._safe_int(getattr(flow, "protocol", 0)),
            "src_port": 0,
            "dst_port": 0,
            "duration": 0.0,
            "byte_rate": 0.0,
            "packet_count": 1,
            "payload_entropy": 0.0,
            "is_encrypted": False,
            "tls_version": None,
            "ja3_hash": None,
            "dns_query_length": 0,
            "http_method": None,
            "has_credentials": False,
        }

        source = getattr(flow, "source", "")
        destination = getattr(flow, "destination", "")

        if ":" in source:
            try:
                features["src_port"] = int(source.split(":")[-1])
            except (ValueError, IndexError):
                pass

        if ":" in destination:
            try:
                features["dst_port"] = int(destination.split(":")[-1])
            except (ValueError, IndexError):
                pass

        features["is_encrypted"] = features["dst_port"] in {443, 465, 993, 995, 5061}
        features["byte_rate"] = float(features["packet_size"])
        features["payload_entropy"] = self._calculate_entropy(
            str(flow.source) + str(flow.destination)
        )

        return features

    def extract_batch(self, flows: List) -> List[Dict]:
        return [self.extract(flow) for flow in flows]

    def get_feature_vector(self, features: Dict) -> List[float]:
        ordered_keys = [
            "packet_size",
            "protocol",
            "src_port",
            "dst_port",
            "duration",
            "byte_rate",
            "packet_count",
            "payload_entropy",
            "is_encrypted",
            "dns_query_length",
        ]

        vector = []
        for key in ordered_keys:
            value = features.get(key, 0)
            if isinstance(value, bool):
                value = 1.0 if value else 0.0
            else:
                value = float(value)
            vector.append(value)

        return vector

    def get_feature_names(self) -> List[str]:
        return [
            "packet_size",
            "protocol",
            "src_port",
            "dst_port",
            "duration",
            "byte_rate",
            "packet_count",
            "payload_entropy",
            "is_encrypted",
            "dns_query_length",
        ]

    def _safe_int(self, value, default=0):
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def _calculate_entropy(self, data: str) -> float:
        if not data:
            return 0.0

        frequency = {}
        for char in data:
            frequency[char] = frequency.get(char, 0) + 1

        entropy = 0.0
        length = len(data)
        for count in frequency.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _check_credentials(self, payload: bytes) -> bool:
        if not payload:
            return False
        return any(pattern.search(payload) for pattern in self.credential_patterns)

    def _detect_tls_version(self, flow) -> Optional[str]:
        destination = getattr(flow, "destination", "")
        if ":" in destination:
            try:
                port = int(destination.split(":")[-1])
                if port == 443:
                    return "TLS"
                elif port == 993:
                    return "TLS/IMAP"
                elif port == 995:
                    return "TLS/POP3"
            except (ValueError, IndexError):
                pass
        return None
