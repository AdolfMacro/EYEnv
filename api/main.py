from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

app = FastAPI(
    title="EYE Network Vision API",
    description="AI-powered network security analysis API",
    version="0.1.0",
)


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
    return {"status": "ok"}


@app.post("/api/v1/flows")
def ingest_flow(flow: FlowIngest):
    return {"status": "received", "flow": flow.dict()}


@app.get("/api/v1/alerts")
def get_alerts(limit: int = 100):
    return []


@app.get("/api/v1/profiles")
def get_profiles():
    return []


@app.get("/api/v1/profiles/{ip}")
def get_profile(ip: str):
    return None
