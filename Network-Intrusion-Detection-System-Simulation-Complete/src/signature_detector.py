from typing import Dict, List


def detect_signatures(flow: Dict) -> List[Dict]:
    """Apply transparent, configurable rule-based checks to one synthetic flow."""
    alerts = []
    base = {"flow_id": int(flow["flow_id"]), "source_ip": flow["source_ip"], "destination_ip": flow["destination_ip"]}
    rules = [
        (int(flow["unique_destination_ports"]) >= 15, "SIG-001", "Port Scan Detection", "high", f"Source {flow['source_ip']} contacted {flow['unique_destination_ports']} unique destination ports."),
        (int(flow["failed_connections"]) >= 10, "SIG-002", "Brute Force Detection", "high", f"Detected {flow['failed_connections']} failed connections towards destination port {flow['destination_port']} ."),
        (int(flow["packet_count"]) >= 2000, "SIG-003", "High Packet Rate Detection", "critical", f"Flow contains {flow['packet_count']} packets, above the configured threshold."),
        (int(flow["byte_count"]) >= 5_000_000, "SIG-004", "Large Data Transfer Detection", "high", f"Flow contains approximately {int(flow['byte_count']):,} transferred bytes."),
    ]
    for matched, rule_id, name, severity, description in rules:
        if matched:
            alerts.append({**base, "rule_id": rule_id, "rule_name": name, "severity": severity, "description": description})
    return alerts
