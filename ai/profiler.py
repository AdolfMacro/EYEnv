import math
from collections import defaultdict
from typing import Dict, List, Optional


class BehavioralProfiler:
    def __init__(self):
        self.baselines: Dict[str, Dict[str, Any]] = {}
        self.default_baseline = {
            "mean_packet_size": 0.0,
            "std_packet_size": 0.0,
            "mean_byte_rate": 0.0,
            "std_byte_rate": 0.0,
            "common_ports": [],
            "common_protocols": [],
            "active_hours": [0] * 24,
            "frequent_partners": [],
            "inbound_ratio": 0.0,
            "flow_count": 0,
        }

    def build_baseline(self, ip: str, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not flows:
            return self.default_baseline.copy()

        packet_sizes = [f.get("packet_size", 0) for f in flows]
        byte_rates = [f.get("byte_rate", 0.0) for f in flows]
        ports = [f.get("dst_port", 0) for f in flows if f.get("dst_port", 0) > 0]
        protocols = [str(f.get("protocol", 0)) for f in flows]
        hours = [0] * 24

        for flow in flows:
            ts = flow.get("timestamp", "")
            if ts:
                try:
                    hour = int(ts.split("T")[-1].split(":")[0])
                    hours[hour % 24] += 1
                except (ValueError, IndexError):
                    pass

        port_counter: Dict[int, int] = defaultdict(int)
        for port in ports:
            port_counter[port] += 1

        proto_counter: Dict[str, int] = defaultdict(int)
        for proto in protocols:
            proto_counter[proto] += 1

        inbound_count = sum(1 for f in flows if f.get("is_inbound", False))
        total_count = len(flows)

        baseline = {
            "mean_packet_size": sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0.0,
            "std_packet_size": self._std(packet_sizes),
            "mean_byte_rate": sum(byte_rates) / len(byte_rates) if byte_rates else 0.0,
            "std_byte_rate": self._std(byte_rates),
            "common_ports": sorted(port_counter.items(), key=lambda x: x[1], reverse=True)[:10],
            "common_protocols": sorted(proto_counter.items(), key=lambda x: x[1], reverse=True)[:5],
            "active_hours": hours,
            "frequent_partners": [],
            "inbound_ratio": inbound_count / total_count if total_count > 0 else 0.0,
            "flow_count": total_count,
        }

        self.baselines[ip] = baseline
        return baseline

    def update_baseline(self, ip: str, new_flows: List[Dict[str, Any]], alpha: float = 0.1):
        if ip not in self.baselines:
            self.build_baseline(ip, new_flows)
            return

        baseline = self.baselines[ip]
        current_count = baseline.get("flow_count", 0)
        total_count = current_count + len(new_flows)
        weight = len(new_flows) / total_count if total_count > 0 else 0.0

        new_baseline = self.build_baseline(ip, new_flows)

        for key in self.default_baseline:
            if key in ("common_ports", "common_protocols", "frequent_partners", "active_hours"):
                continue

            old_val = baseline.get(key, 0.0)
            new_val = new_baseline.get(key, 0.0)
            baseline[key] = old_val + weight * (new_val - old_val)

        baseline["flow_count"] = total_count
        self.baselines[ip] = baseline

    def get_baseline(self, ip: str) -> Optional[Dict[str, Any]]:
        return self.baselines.get(ip)

    def deviation_score(self, ip: str, features: Dict[str, Any]) -> float:
        baseline = self.get_baseline(ip)
        if not baseline:
            return 0.0

        scores = []

        packet_size = features.get("packet_size", 0)
        mean_size = baseline.get("mean_packet_size", 0.0)
        std_size = baseline.get("std_packet_size", 1.0)
        if std_size > 0:
            z_score = abs(packet_size - mean_size) / std_size
            scores.append(min(z_score / 3.0, 1.0))

        byte_rate = features.get("byte_rate", 0.0)
        mean_rate = baseline.get("mean_byte_rate", 0.0)
        std_rate = baseline.get("std_byte_rate", 1.0)
        if std_rate > 0:
            z_score = abs(byte_rate - mean_rate) / std_rate
            scores.append(min(z_score / 3.0, 1.0))

        dst_port = features.get("dst_port", 0)
        common_ports = [p[0] for p in baseline.get("common_ports", [])]
        if common_ports and dst_port not in common_ports:
            scores.append(0.5)

        return sum(scores) / len(scores) if scores else 0.0

    def is_anomalous(self, ip: str, features: Dict[str, Any], threshold: float = 0.7) -> bool:
        return self.deviation_score(ip, features) >= threshold

    def _std(self, values: List[float]) -> float:
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)
