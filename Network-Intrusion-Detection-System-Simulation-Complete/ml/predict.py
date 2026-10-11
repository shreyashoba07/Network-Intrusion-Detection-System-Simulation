from pathlib import Path
from functools import lru_cache
import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "network_ids_ml_model.pkl"
FEATURES_PATH = ROOT / "models" / "network_ids_features.pkl"
FEATURES = ["source_port", "destination_port", "packet_count", "byte_count", "connection_duration", "failed_connections", "unique_destination_ports"]

@lru_cache(maxsize=1)
def _load_model_and_features():
    return joblib.load(MODEL_PATH), joblib.load(FEATURES_PATH)

def _format_result(malicious, prediction, method):
    severity = "critical" if malicious >= 90 else "high" if malicious >= 70 else "medium" if malicious >= 50 else "low"
    return {"ml_prediction": prediction, "ml_detected": malicious >= 70, "malicious_probability": round(malicious, 2), "benign_probability": round(100-malicious, 2), "ml_severity": severity, "threshold": 70, "model_method": method}

def predict_network_flows(flows):
    """Batch predictions for dataset processing; much faster than predicting row by row."""
    flows = list(flows)
    if not flows: return []
    if MODEL_PATH.exists() and FEATURES_PATH.exists():
        model, features = _load_model_and_features()
        X = pd.DataFrame([{f: float(flow[f]) for f in features} for flow in flows], columns=features)
        predictions = model.predict(X)
        probabilities = model.predict_proba(X)
        classes = list(model.classes_); malicious_index = classes.index(1) if 1 in classes else 0
        return [_format_result(float(prob[malicious_index])*100, "MALICIOUS" if int(pred)==1 else "BENIGN", "trained_random_forest") for pred, prob in zip(predictions, probabilities)]
    results = []
    for flow in flows:
        points = 0
        points += 30 if int(flow["unique_destination_ports"]) >= 15 else 0
        points += 30 if int(flow["failed_connections"]) >= 10 else 0
        points += 30 if int(flow["packet_count"]) >= 1500 else 0
        points += 30 if int(flow["byte_count"]) >= 5_000_000 else 0
        malicious = min(points, 100); results.append(_format_result(malicious, "MALICIOUS" if malicious >= 50 else "BENIGN", "threshold_fallback"))
    return results

def predict_network_flow(flow):
    if MODEL_PATH.exists() and FEATURES_PATH.exists():
        model, features = _load_model_and_features()
        X = pd.DataFrame([{f: float(flow[f]) for f in features}], columns=features)
        probabilities = model.predict_proba(X)[0]
        classes = list(model.classes_); malicious_index = classes.index(1) if 1 in classes else 0
        malicious = float(probabilities[malicious_index]) * 100
        prediction = "MALICIOUS" if int(model.predict(X)[0]) == 1 else "BENIGN"
        method = "trained_random_forest"
    else:
        # Safe fallback to keep the demo usable before the optional model-training step.
        points = 0
        points += 30 if int(flow["unique_destination_ports"]) >= 15 else 0
        points += 30 if int(flow["failed_connections"]) >= 10 else 0
        points += 30 if int(flow["packet_count"]) >= 1500 else 0
        points += 30 if int(flow["byte_count"]) >= 5_000_000 else 0
        malicious = min(points, 100); prediction = "MALICIOUS" if malicious >= 50 else "BENIGN"; method = "threshold_fallback"
    return _format_result(malicious, prediction, method)
