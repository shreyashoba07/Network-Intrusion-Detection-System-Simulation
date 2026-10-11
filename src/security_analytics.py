from collections import Counter
from datetime import datetime


def _severity(alert): return str(alert.get("risk_level", "LOW")).upper()

def generate_security_analytics(flows, alerts):
    flows = list(flows or []); alerts = list(alerts or [])
    normal = sum(str(f.get("label", "benign")).lower() in {"benign", "normal", "0"} for f in flows)
    severity = Counter(_severity(a) for a in alerts)
    status = Counter(str(a.get("alert_status", "NEW")).upper() for a in alerts)
    alert_types = Counter()
    for a in alerts:
        for x in a.get("signature_alerts", []) or []: alert_types[x.get("rule_name", "Signature detection")] += 1
        for x in a.get("anomaly_alerts", []) or []: alert_types[x.get("anomaly_name", "Anomaly detection")] += 1
        if a.get("ml_detected"): alert_types["Machine Learning Detection"] += 1
    source_counts = Counter(a.get("source_ip", "unknown") for a in alerts)
    port_counts = Counter(str(f.get("destination_port", "unknown")) for f in flows)
    protocols = Counter(str(f.get("protocol", "unknown")).upper() for f in flows)
    scenarios = Counter(str(f.get("scenario", "unknown")) for f in flows)
    risk_bins = Counter()
    for a in alerts:
        score = float(a.get("risk_score", 0))
        risk_bins["0–29"] += score < 30
        risk_bins["30–59"] += 30 <= score < 60
        risk_bins["60–79"] += 60 <= score < 80
        risk_bins["80–100"] += score >= 80
    time_counts = Counter()
    for f in flows:
        ts = str(f.get("timestamp", ""))
        if len(ts) >= 13: time_counts[ts[:13].replace("T", " ")] += 1
    return {
        "total_network_flows": len(flows), "normal_traffic": normal,
        "suspicious_traffic": len(flows) - normal, "total_alerts": len(alerts),
        "severity_distribution": dict(severity), "alert_type_distribution": dict(alert_types),
        "top_source_ips": [{"source_ip": k, "alert_count": v} for k, v in source_counts.most_common(10)],
        "risk_score_distribution": dict(risk_bins), "status_distribution": dict(status),
        "scenario_distribution": dict(scenarios), "protocol_distribution": dict(protocols),
        "destination_port_distribution": [{"destination_port": k, "flow_count": v} for k, v in port_counts.most_common(10)],
        "traffic_over_time": [{"timestamp": k, "flow_count": v} for k, v in sorted(time_counts.items())],
        "average_risk_score": round(sum(float(a.get("risk_score", 0)) for a in alerts) / len(alerts), 2) if alerts else 0,
    }
