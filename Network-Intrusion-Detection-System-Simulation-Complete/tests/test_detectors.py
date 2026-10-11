from src.signature_detector import detect_signatures
from src.anomaly_detector import detect_anomalies

def flow(**overrides):
    base = {"flow_id":1,"source_ip":"10.0.0.2","destination_ip":"10.0.4.3","source_port":50000,"destination_port":443,"protocol":"TCP","packet_count":100,"byte_count":10000,"connection_duration":12.0,"failed_connections":0,"unique_destination_ports":2,"scenario":"normal","label":"benign"}
    base.update(overrides); return base

def test_no_signature_for_normal_flow(): assert detect_signatures(flow()) == []
def test_port_scan_signature(): assert any(a["rule_id"]=="SIG-001" for a in detect_signatures(flow(unique_destination_ports=15)))
def test_brute_force_signature(): assert any(a["rule_id"]=="SIG-002" for a in detect_signatures(flow(failed_connections=10)))
def test_packet_rate_signature(): assert any(a["rule_id"]=="SIG-003" for a in detect_signatures(flow(packet_count=2000)))
def test_large_transfer_signature(): assert any(a["rule_id"]=="SIG-004" for a in detect_signatures(flow(byte_count=5_000_000)))
def test_packet_anomaly_threshold(): assert any(a["anomaly_id"]=="ANOM-001" for a in detect_anomalies(flow(packet_count=1501)))
def test_byte_anomaly_threshold(): assert any(a["anomaly_id"]=="ANOM-002" for a in detect_anomalies(flow(byte_count=5_000_001)))
def test_failed_connection_anomaly(): assert any(a["anomaly_id"]=="ANOM-003" for a in detect_anomalies(flow(failed_connections=9)))
def test_port_diversity_anomaly(): assert any(a["anomaly_id"]=="ANOM-004" for a in detect_anomalies(flow(unique_destination_ports=11)))
def test_duration_anomaly(): assert any(a["anomaly_id"]=="ANOM-005" for a in detect_anomalies(flow(connection_duration=501)))
def test_signature_returns_list(): assert isinstance(detect_signatures(flow()), list)
def test_anomaly_returns_list(): assert isinstance(detect_anomalies(flow()), list)
def test_signature_alert_has_description():
    a=detect_signatures(flow(packet_count=2000))[0]; assert a["description"] and a["severity"]
def test_anomaly_alert_has_source():
    a=detect_anomalies(flow(packet_count=2000))[0]; assert a["source_ip"] == "10.0.0.2"
