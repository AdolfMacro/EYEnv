from datetime import datetime
from typing import Dict, List, Optional

from ai.inspector import PayloadInspector


class AlertEngine:
    SEVERITY_LEVELS = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    def __init__(self, storage):
        self.storage = storage
        self.inspector = PayloadInspector()

    def evaluate(
        self,
        segment_id: str,
        flow,
        features: Dict[str, any],
        anomaly_result: Dict[str, any],
        payload: Optional[bytes] = None,
    ) -> List[Dict[str, any]]:
        alerts = []

        if anomaly_result.get("is_anomaly"):
            severity = self._score_to_severity(anomaly_result.get("anomaly_score", 0.0))
            alerts.append({
                "severity": severity,
                "category": "anomaly",
                "description": self._format_anomaly_description(anomaly_result),
                "flow_id": getattr(flow, "id", None),
                "score": anomaly_result.get("anomaly_score", 0.0),
            })

        if payload:
            inspection = self.inspector.inspect(flow, payload)
            if inspection.get("has_credentials"):
                alerts.append({
                    "severity": "HIGH",
                    "category": "payload",
                    "description": "Possible credentials detected in payload",
                    "flow_id": getattr(flow, "id", None),
                    "score": 0.8,
                })
            if inspection.get("has_suspicious_content"):
                alerts.append({
                    "severity": "MEDIUM",
                    "category": "payload",
                    "description": f"Suspicious patterns detected: {', '.join(inspection.get('suspicious_patterns', [])[:3])}",
                    "flow_id": getattr(flow, "id", None),
                    "score": 0.6,
                })

        for alert in alerts:
            if self.storage:
                self.storage.insert_alert(
                    severity=alert["severity"],
                    category=alert["category"],
                    description=alert["description"],
                    flow_id=alert.get("flow_id"),
                    score=alert.get("score", 0.0),
                )

        return alerts

    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, any]]:
        if self.storage:
            return self.storage.get_alerts(limit)
        return []

    def _score_to_severity(self, score: float) -> str:
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"

    def _format_anomaly_description(self, anomaly_result: Dict[str, any]) -> str:
        reasons = anomaly_result.get("reasons", [])
        if reasons:
            return f"Anomaly detected: {'; '.join(reasons)}"
        return f"Anomaly detected with score {anomaly_result.get('anomaly_score', 0.0):.2f}"
