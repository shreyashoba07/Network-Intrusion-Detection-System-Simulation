from pathlib import Path
import pandas as pd
from src.ids_engine import analyze_network_flow
from ml.predict import predict_network_flows

ROOT = Path(__file__).resolve().parents[1]
def process_dataset(limit=None):
    path = ROOT / "data" / "network_traffic.csv"
    if not path.exists(): raise FileNotFoundError("Run python data/generate_traffic.py first.")
    df = pd.read_csv(path)
    if limit: df = df.head(limit)
    rows = df.to_dict(orient="records")
    predictions = predict_network_flows(rows)
    detected = 0
    for row, ml_result in zip(rows, predictions):
        result = analyze_network_flow(row, persist=True, ml_result=ml_result)
        if result["total_alert_count"] > 0 or result["ml_detected"]: detected += 1
    print(f"Processed {len(df):,} synthetic flows; stored/updated {detected:,} alert records.")
    return {"processed": len(df), "alerts": detected}
if __name__ == "__main__": process_dataset()
