from pathlib import Path
import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ["source_port", "destination_port", "packet_count", "byte_count", "connection_duration", "failed_connections", "unique_destination_ports"]

def train():
    data_path = ROOT / "data" / "network_traffic.csv"
    if not data_path.exists(): raise FileNotFoundError("Run python data/generate_traffic.py first.")
    df = pd.read_csv(data_path)
    X = df[FEATURES].fillna(0)
    y = (df["label"].astype(str).str.lower() == "malicious").astype(int)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced", n_jobs=-1)
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    metrics = {"test_records": int(len(y_test)), "accuracy": round(accuracy_score(y_test, pred), 4), "precision": round(precision_score(y_test, pred, zero_division=0), 4), "recall": round(recall_score(y_test, pred, zero_division=0), 4), "f1": round(f1_score(y_test, pred, zero_division=0), 4), "confusion_matrix": confusion_matrix(y_test, pred).tolist(), "note": "Synthetic dataset evaluation only; not evidence of real-world performance."}
    (ROOT / "models").mkdir(exist_ok=True); (ROOT / "reports").mkdir(exist_ok=True)
    joblib.dump(model, ROOT / "models" / "network_ids_ml_model.pkl")
    joblib.dump(FEATURES, ROOT / "models" / "network_ids_features.pkl")
    (ROOT / "reports" / "ml_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    return metrics

if __name__ == "__main__": train()
