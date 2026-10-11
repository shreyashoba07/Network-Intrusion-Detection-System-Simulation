from datetime import datetime
from src.signature_detector import detect_signatures
from src.anomaly_detector import detect_anomalies
from src.risk_scorer import get_risk_level
from ml.predict import predict_network_flow
from backend.database import save_alert, get_alert_by_id

SIGNATURE_WEIGHT = 0.40
ANOMALY_WEIGHT = 0.30
ML_WEIGHT = 0.30

def analyze_network_flow(flow, persist=True, ml_result=None):
    signatures = detect_signatures(flow); anomalies = detect_anomalies(flow); ml = ml_result or predict_network_flow(flow)
    signature_score = min(len(signatures) * 25, 100)
    anomaly_score = min(len(anomalies) * 25, 100)
    ml_score = float(ml["malicious_probability"])
    hybrid_score = round(min(signature_score*SIGNATURE_WEIGHT + anomaly_score*ANOMALY_WEIGHT + ml_score*ML_WEIGHT, 100), 2)
    level = get_risk_level(hybrid_score)
    alert = {
        "alert_id": f"ALERT-{int(flow['flow_id']):06d}", "flow_id": int(flow["flow_id"]),
        "timestamp": str(flow.get("timestamp") or datetime.now().isoformat(timespec="seconds")),
        "source_ip": str(flow["source_ip"]), "destination_ip": str(flow["destination_ip"]),
        "scenario": str(flow.get("scenario", "manual_analysis")), "label": str(flow.get("label", "unknown")),
        "risk_score": hybrid_score, "risk_level": level, "alert_status": "NEW",
        "signature_alert_count": len(signatures), "anomaly_alert_count": len(anomalies),
        "total_alert_count": len(signatures)+len(anomalies), "signature_alerts": signatures,
        "anomaly_alerts": anomalies, "analyst_notes": "", **ml,
        "hybrid_score": hybrid_score, "hybrid_level": level,
        "signature_score": signature_score, "anomaly_score": anomaly_score, "ml_score": ml_score,
        "signature_weight": SIGNATURE_WEIGHT, "anomaly_weight": ANOMALY_WEIGHT, "ml_weight": ML_WEIGHT,
    }
    if persist and (signatures or anomalies or ml["ml_detected"]):
        existing = get_alert_by_id(alert["alert_id"])
        if existing:
            alert["alert_status"] = existing.get("alert_status", "NEW")
            alert["analyst_notes"] = existing.get("analyst_notes", "")
        save_alert(alert)
    return alert
