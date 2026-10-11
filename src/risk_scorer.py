from typing import Dict, List
SEVERITY_POINTS = {"low": 10, "medium": 20, "high": 30, "critical": 40}

def get_risk_level(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"

def calculate_risk_score(signature_alerts: List[Dict], anomaly_alerts: List[Dict]) -> Dict:
    score = sum(SEVERITY_POINTS.get(a.get("severity", "low").lower(), 10) for a in signature_alerts + anomaly_alerts)
    score = min(score, 100)
    return {"risk_score": score, "risk_level": get_risk_level(score), "signature_alert_count": len(signature_alerts), "anomaly_alert_count": len(anomaly_alerts), "total_alert_count": len(signature_alerts) + len(anomaly_alerts)}
