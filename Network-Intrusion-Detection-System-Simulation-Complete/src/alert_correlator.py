from datetime import datetime
from collections import defaultdict


def _alert_types(alert):
    names = []
    for item in alert.get("signature_alerts", []) or []:
        names.append("SIGNATURE:" + str(item.get("rule_id", item.get("rule_name", "unknown"))))
    for item in alert.get("anomaly_alerts", []) or []:
        names.append("ANOMALY:" + str(item.get("anomaly_id", item.get("anomaly_name", "unknown"))))
    if not names: names.append("ML:" + str(alert.get("ml_prediction", "DETECTION")))
    return sorted(set(names))


def correlate_alerts(alerts, time_window_seconds=300):
    if time_window_seconds <= 0 or time_window_seconds > 3600:
        raise ValueError("Time window must be between 1 and 3600 seconds.")
    buckets = defaultdict(list)
    for alert in alerts:
        try: ts = datetime.fromisoformat(str(alert.get("timestamp", "")).replace("Z", "+00:00"))
        except (ValueError, TypeError): continue
        for kind in _alert_types(alert):
            buckets[(alert.get("source_ip", "unknown"), kind)].append((ts, alert))
    groups = []
    for (source_ip, kind), items in buckets.items():
        items.sort(key=lambda x: x[0])
        current = []
        start = None
        for ts, alert in items:
            if start is None or (ts - start).total_seconds() <= time_window_seconds:
                if start is None: start = ts
                current.append(alert)
            else:
                if current: groups.append((source_ip, kind, current, start))
                current = [alert]; start = ts
        if current: groups.append((source_ip, kind, current, start))
    output = []
    for idx, (source_ip, kind, members, start) in enumerate(groups, 1):
        output.append({"correlation_id": f"CORR-{idx:04d}", "source_ip": source_ip, "alert_type": kind, "alert_count": len(members), "max_risk_score": max(float(a.get("risk_score", 0)) for a in members), "first_seen": start.isoformat(), "alert_ids": sorted(set(str(a.get("alert_id", "")) for a in members))})
    return {"total_alerts": len(alerts), "total_correlation_groups": len(output), "correlated_groups": sum(g["alert_count"] > 1 for g in output), "time_window_seconds": time_window_seconds, "groups": output}
