from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import json

from tools.storage import DataStore
from features import FeatureExtractor
from ai import AnomalyDetector, AlertEngine

app = FastAPI(
    title="EYE Network Vision API",
    description="AI-powered network security analysis API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

storage = DataStore("api_eye_network.db")
feature_extractor = FeatureExtractor()
anomaly_detector = AnomalyDetector(storage)
alert_engine = AlertEngine(storage)


class FlowIngest(BaseModel):
    segment_id: str
    source: str
    destination: str
    protocol: int
    size: int
    classification: Optional[str] = "UNKNOWN"


class AlertResponse(BaseModel):
    id: int
    severity: str
    category: str
    description: str
    flow_id: Optional[int]
    score: float
    timestamp: str
    acknowledged: bool


class ProfileResponse(BaseModel):
    ip: str
    baseline: dict
    last_seen: str
    flow_count: int


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


@app.post("/api/v1/flows")
def ingest_flow(flow: FlowIngest):
    flow_id = storage.insert_flow(flow.segment_id, flow)
    return {"status": "received", "flow_id": flow_id}


@app.get("/api/v1/alerts")
def get_alerts(limit: int = 100):
    alerts = storage.get_alerts(limit)
    return [
        {
            "id": a["id"],
            "severity": a["severity"],
            "category": a["category"],
            "description": a["description"],
            "flow_id": a["flow_id"],
            "score": a["score"],
            "timestamp": a["timestamp"],
            "acknowledged": bool(a["acknowledged"]),
        }
        for a in alerts
    ]


@app.post("/api/v1/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: int):
    storage.acknowledge_alert(alert_id)
    return {"status": "acknowledged", "alert_id": alert_id}


@app.get("/api/v1/profiles")
def get_profiles():
    profiles = storage.get_segments()
    return profiles


@app.get("/api/v1/profiles/{ip}")
def get_profile(ip: str):
    profile = storage.get_profile(ip)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@app.get("/api/v1/flows")
def get_flows(segment_id: str, limit: int = 1000):
    flows = storage.get_recent_flows(segment_id, limit)
    return flows


@app.get("/api/v1/features/{flow_id}")
def get_features(flow_id: int):
    features = storage.get_features_for_flow(flow_id)
    if not features:
        raise HTTPException(status_code=404, detail="Features not found")
    return features


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            alerts = storage.get_alerts(limit=50)
            await websocket.send_json({
                "type": "alerts",
                "data": [
                    {
                        "id": a["id"],
                        "severity": a["severity"],
                        "category": a["category"],
                        "description": a["description"],
                        "score": a["score"],
                        "timestamp": a["timestamp"],
                    }
                    for a in alerts
                ],
            })
            import asyncio
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
