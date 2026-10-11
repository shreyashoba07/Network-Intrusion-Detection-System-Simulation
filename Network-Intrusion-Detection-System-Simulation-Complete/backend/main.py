from pathlib import Path
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from backend.database import get_all_alerts, get_alert_by_id, get_alert_statistics, update_alert_status, update_analyst_notes
from src.ids_engine import analyze_network_flow
from src.alert_correlator import correlate_alerts
from src.security_analytics import generate_security_analytics

ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="Network Intrusion Detection System", description="Defensive, synthetic Network-Based Hybrid IDS simulation", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class NetworkFlow(BaseModel):
    flow_id: int = Field(ge=1)
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    protocol: str
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    connection_duration: float = Field(ge=0)
    failed_connections: int = Field(ge=0)
    unique_destination_ports: int = Field(ge=0)
    scenario: str = "manual_analysis"
    label: str = "unknown"
class StatusUpdate(BaseModel): status: str
class AnalystNote(BaseModel): notes: str = Field(max_length=5000)

@app.get("/")
def root(): return {"message": "Network Intrusion Detection System is running", "status": "online"}
@app.get("/health")
def health(): return {"status": "healthy", "service": "Network IDS Backend"}
@app.post("/analyze")
def analyze(flow: NetworkFlow):
    try: return {"message": "Synthetic network flow analyzed successfully", "alert": analyze_network_flow(flow.model_dump())}
    except Exception as exc: raise HTTPException(500, detail=f"Analysis failed: {exc}")
@app.get("/alerts")
def alerts(limit: int = Query(2000, ge=1, le=10000), severity: str | None = None, status: str | None = None, protocol: str | None = None, search: str | None = None):
    items = get_all_alerts(limit=10000)
    if severity: items = [a for a in items if a.get("risk_level") == severity.upper()]
    if status: items = [a for a in items if a.get("alert_status") == status.upper()]
    if protocol:
        # Protocol is included in source flow analytics; individual stored alerts may not contain it.
        items = [a for a in items if str(a.get("protocol", "")).upper() == protocol.upper()]
    if search:
        term = search.lower(); items = [a for a in items if term in str(a.get("alert_id", "")).lower() or term in str(a.get("source_ip", "")).lower() or term in str(a.get("destination_ip", "")).lower() or term in str(a.get("scenario", "")).lower()]
    return {"total": len(items), "alerts": items[:limit]}
@app.get("/alerts/{alert_id}")
def one_alert(alert_id: str):
    item = get_alert_by_id(alert_id)
    if not item: raise HTTPException(404, "Alert not found")
    return item
@app.put("/alerts/{alert_id}/status")
def status_update(alert_id: str, body: StatusUpdate):
    try: updated = update_alert_status(alert_id, body.status)
    except ValueError as exc: raise HTTPException(400, str(exc))
    if not updated: raise HTTPException(404, "Alert not found")
    return {"message": "Status updated", "alert_id": alert_id, "status": body.status.upper()}
@app.put("/alerts/{alert_id}/notes")
def notes_update(alert_id: str, body: AnalystNote):
    try: updated = update_analyst_notes(alert_id, body.notes)
    except (ValueError, TypeError) as exc: raise HTTPException(400, str(exc))
    if not updated: raise HTTPException(404, "Alert not found")
    return {"message": "Analyst notes saved", "alert_id": alert_id}
@app.get("/stats")
def stats(): return get_alert_statistics()
@app.get("/correlations")
def correlations(time_window_seconds: int = Query(300, ge=1, le=3600)):
    return correlate_alerts(get_all_alerts(limit=10000), time_window_seconds)
@app.get("/analytics")
def analytics():
    path = ROOT / "data" / "network_traffic.csv"
    if not path.exists(): raise HTTPException(404, "Dataset not found. Run python data/generate_traffic.py first.")
    flows = pd.read_csv(path).to_dict(orient="records")
    return generate_security_analytics(flows, get_all_alerts(limit=10000))
@app.post("/simulate")
def simulate(count: int = Query(1, ge=1, le=100)):
    path = ROOT / "data" / "network_traffic.csv"
    if not path.exists(): raise HTTPException(404, "Dataset not found. Generate it first.")
    df = pd.read_csv(path)
    sample = df.sample(n=min(count, len(df)), random_state=None).to_dict(orient="records")
    results = [analyze_network_flow(row) for row in sample]
    return {"simulated": len(results), "alerts_generated": sum(bool(r["total_alert_count"] or r["ml_detected"]) for r in results), "results": results}
