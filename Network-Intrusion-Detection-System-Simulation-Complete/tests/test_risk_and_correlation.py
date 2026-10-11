import pytest
from src.risk_scorer import calculate_risk_score, get_risk_level
from src.alert_correlator import correlate_alerts

def test_zero_risk_is_low(): assert get_risk_level(0)=="LOW"
def test_medium_boundary(): assert get_risk_level(30)=="MEDIUM"
def test_high_boundary(): assert get_risk_level(60)=="HIGH"
def test_critical_boundary(): assert get_risk_level(80)=="CRITICAL"
def test_risk_score_caps_at_100(): assert calculate_risk_score([{"severity":"critical"}]*5,[])["risk_score"]==100
def test_risk_counts_both_detectors():
    r=calculate_risk_score([{"severity":"high"}],[{"severity":"medium"}]); assert r["total_alert_count"]==2 and r["risk_score"]==50
def test_unknown_severity_uses_safe_default(): assert calculate_risk_score([{"severity":"other"}],[])["risk_score"]==10
def test_correlation_rejects_zero_window():
    with pytest.raises(ValueError): correlate_alerts([],0)
def test_correlation_rejects_large_window():
    with pytest.raises(ValueError): correlate_alerts([],3601)
def test_empty_correlation_result(): assert correlate_alerts([])["total_correlation_groups"]==0
def test_correlates_same_source_and_type():
    alerts=[{"alert_id":"A","timestamp":"2026-09-01T00:00:00","source_ip":"10.0.0.1","risk_score":70,"signature_alerts":[{"rule_id":"SIG-001"}]},{"alert_id":"B","timestamp":"2026-09-01T00:02:00","source_ip":"10.0.0.1","risk_score":80,"signature_alerts":[{"rule_id":"SIG-001"}]}]
    result=correlate_alerts(alerts); assert result["correlated_groups"]==1
