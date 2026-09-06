import math
import math
from typing import Dict, List, Optional, Tuple

from ai.profiler import BehavioralProfiler


class AnomalyDetector:
    def __init__(self, storage):
        self.profiler = BehavioralProfiler()
        self.storage = storage
        self.rule_thresholds = {
            "port_scan_window_seconds": 60,
            "port_scan_unique_ports": 10,
            "dns_entropy_threshold": 4.5,
            "dns_response_bytes_threshold": 1000,
        }

    def detect(self, segment_id: str, flow, features: Dict[str, Any]) -> Dict[str, Any]:
        scores = {}
        triggered = []
        ip = getattr(flow, "source", "")

        scores["statistical"], stat_triggered = self._statistical_check(ip, features)
        scores["isolation_forest"] = 0.0
        scores["rule_based"], rule_triggered = self._rule_based_check(segment_id, flow, features)

        triggered.extend(stat_triggered)
        triggered.extend(rule_triggered)

        anomaly_score = max(scores.values())
        is_anomaly = anomaly_score >= 0.6 or bool(triggered)

        return {
            "flow_id": getattr(flow, "id", None),
            "anomaly_score": round(anomaly_score, 3),
            "detectors": scores,
            "is_anomaly": is_anomaly,
            "reasons": triggered,
        }

    def update_profiles(self, segment_id: str, flows: List[Dict[str, Any]]):
        ip_flows: Dict[str, List[Dict[str, Any]]] = {}
        for flow in flows:
            ip = flow.get("source", "")
            if ip:
                ip_flows.setdefault(ip, []).append(flow)

        for ip, ip_flow_list in ip_flows.items():
            baseline = self.profiler.get_baseline(ip)
            if baseline and baseline.get("flow_count", 0) >= 50:
                self.profiler.update_baseline(ip, ip_flow_list)
            else:
                self.profiler.build_baseline(ip, ip_flow_list)

            if self.storage:
                self.storage.upsert_profile(ip, self.profiler.get_baseline(ip) or {}, len(ip_flow_list))

    def _statistical_check(self, ip: str, features: Dict[str, Any]) -> Tuple[float, List[str]]:
        reasons = []
        score = 0.0

        deviation = self.profiler.deviation_score(ip, features)
        if deviation > 0.7:
            score = max(score, 0.8)
            reasons.append("High statistical deviation")
        elif deviation > 0.4:
            score = max(score, 0.5)
            reasons.append("Moderate statistical deviation")

        return score, reasons

    def _rule_based_check(self, segment_id: str, flow, features: Dict[str, Any]) -> Tuple[float, List[str]]:
        reasons = []
        score = 0.0

        dst_port = features.get("dst_port", 0)
        if self._is_suspicious_port(dst_port):
            score = max(score, 0.7)
            reasons.append(f"Suspicious port: {dst_port}")

        entropy = features.get("payload_entropy", 0.0)
        if entropy > 7.5:
            score = max(score, 0.6)
            reasons.append("High payload entropy")

        if features.get("has_credentials", False):
            score = max(score, 0.8)
            reasons.append("Possible credentials in payload")

        if features.get("is_encrypted", False):
            score = max(score, 0.3)
            reasons.append("Encrypted traffic")

        return score, reasons

    def _is_suspicious_port(self, port: int) -> bool:
        suspicious_ports = {23, 2323, 4444, 5555, 6667, 12345, 31337, 54321}
        return port in suspicious_ports

    def _calculate_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        frequency: Dict[str, int] = {}
        for char in data:
            frequency[char] = frequency.get(char, 0) + 1
        entropy = 0.0
        length = len(data)
        for count in frequency.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy
