from typing import Dict, List


def detect_anomalies(flow: Dict) -> List[Dict]:
    alerts = []
    base = {"flow_id": int(flow["flow_id"]), "source_ip": flow["source_ip"], "destination_ip": flow["destination_ip"]}
    checks = [
        (int(flow["packet_count"]) > 1500, "ANOM-001", "Unusually High Packet Count", "high", f"Packet count {flow['packet_count']} exceeds 1,500."),
        (int(flow["byte_count"]) > 5_000_000, "ANOM-002", "Unusually Large Data Transfer", "high", f"Byte count {int(flow['byte_count']):,} exceeds 5,000,000."),
        (int(flow["failed_connections"]) > 8, "ANOM-003", "High Failed Connection Count", "medium", f"Failed connections {flow['failed_connections']} exceeds 8."),
        (int(flow["unique_destination_ports"]) > 10, "ANOM-004", "High Destination Port Diversity", "high", f"Unique destination ports {flow['unique_destination_ports']} exceeds 10."),
        (float(flow["connection_duration"]) > 500, "ANOM-005", "Unusually Long Connection", "medium", f"Connection duration {flow['connection_duration']} seconds exceeds 500 seconds."),
    ]
    for matched, anomaly_id, name, severity, description in checks:
        if matched:
            alerts.append({**base, "anomaly_id": anomaly_id, "anomaly_name": name, "severity": severity, "description": description})
    return alerts
