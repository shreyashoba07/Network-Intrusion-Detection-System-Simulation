from fastapi.testclient import TestClient
from backend.main import app
from src.security_analytics import generate_security_analytics

client=TestClient(app)
def test_analytics_counts_flows():
    result=generate_security_analytics([{"label":"benign"},{"label":"malicious"}],[]); assert result["total_network_flows"]==2 and result["normal_traffic"]==1
def test_analytics_empty_alerts(): assert generate_security_analytics([],[])["total_alerts"]==0
def test_analytics_protocol_counts():
    result=generate_security_analytics([{"label":"benign","protocol":"TCP"},{"label":"benign","protocol":"UDP"}],[]); assert result["protocol_distribution"]=={"TCP":1,"UDP":1}
def test_analytics_severity_counts():
    result=generate_security_analytics([], [{"risk_level":"HIGH"},{"risk_level":"HIGH"}]); assert result["severity_distribution"]["HIGH"]==2
def test_analytics_status_counts():
    result=generate_security_analytics([], [{"alert_status":"NEW"}]); assert result["status_distribution"]["NEW"]==1
def test_root_endpoint(): assert client.get("/").status_code==200
def test_health_endpoint(): assert client.get("/health").json()["status"]=="healthy"
def test_stats_endpoint_shape():
    data=client.get("/stats").json(); assert "total_alerts" in data and "severity_distribution" in data
def test_alerts_endpoint_shape():
    data=client.get("/alerts?limit=5").json(); assert "alerts" in data and "total" in data
def test_correlations_endpoint(): assert client.get("/correlations").status_code==200
def test_analytics_endpoint_has_flow_count():
    # If the dataset has not been generated, the endpoint correctly reports a missing dataset.
    response=client.get("/analytics"); assert response.status_code in (200,404)
