from pathlib import Path
import json, sqlite3
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "backend" / "ids.sqlite3"


@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY, flow_id INTEGER, timestamp TEXT, source_ip TEXT, destination_ip TEXT,
            scenario TEXT, label TEXT, risk_score REAL, risk_level TEXT, alert_status TEXT DEFAULT 'NEW',
            signature_alert_count INTEGER DEFAULT 0, anomaly_alert_count INTEGER DEFAULT 0, total_alert_count INTEGER DEFAULT 0,
            signature_alerts TEXT DEFAULT '[]', anomaly_alerts TEXT DEFAULT '[]', analyst_notes TEXT DEFAULT '',
            ml_prediction TEXT DEFAULT 'UNKNOWN', ml_detected INTEGER DEFAULT 0, malicious_probability REAL DEFAULT 0,
            benign_probability REAL DEFAULT 100, ml_severity TEXT DEFAULT 'low', hybrid_score REAL DEFAULT 0,
            hybrid_level TEXT DEFAULT 'LOW', signature_score REAL DEFAULT 0, anomaly_score REAL DEFAULT 0, ml_score REAL DEFAULT 0,
            signature_weight REAL DEFAULT 0.4, anomaly_weight REAL DEFAULT 0.3, ml_weight REAL DEFAULT 0.3
        )""")
        conn.commit()


def _decode(row):
    if row is None: return None
    item = dict(row)
    for key in ("signature_alerts", "anomaly_alerts"):
        try: item[key] = json.loads(item.get(key) or "[]")
        except (json.JSONDecodeError, TypeError): item[key] = []
    item["ml_detected"] = bool(item.get("ml_detected", 0))
    return item


def save_alert(alert):
    columns = ["alert_id", "flow_id", "timestamp", "source_ip", "destination_ip", "scenario", "label", "risk_score", "risk_level", "alert_status", "signature_alert_count", "anomaly_alert_count", "total_alert_count", "signature_alerts", "anomaly_alerts", "analyst_notes", "ml_prediction", "ml_detected", "malicious_probability", "benign_probability", "ml_severity", "hybrid_score", "hybrid_level", "signature_score", "anomaly_score", "ml_score", "signature_weight", "anomaly_weight", "ml_weight"]
    values = []
    for c in columns:
        value = alert.get(c)
        if c in ("signature_alerts", "anomaly_alerts"): value = json.dumps(value or [])
        if c == "ml_detected": value = int(bool(value))
        values.append(value)
    marks = ",".join("?" for _ in columns)
    updates = ",".join(f"{c}=excluded.{c}" for c in columns if c != "alert_id")
    with connect() as conn:
        conn.execute(f"INSERT INTO alerts ({','.join(columns)}) VALUES ({marks}) ON CONFLICT(alert_id) DO UPDATE SET {updates}", values)
        conn.commit()


def get_all_alerts(limit=2000):
    init_db()
    with connect() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC, alert_id DESC LIMIT ?", (int(limit),)).fetchall()
    return [_decode(r) for r in rows]


def get_alert_by_id(alert_id):
    init_db()
    with connect() as conn: row = conn.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    return _decode(row)


def update_alert_status(alert_id, status):
    status = str(status).upper()
    if status not in {"NEW", "INVESTIGATING", "RESOLVED"}: raise ValueError("Status must be NEW, INVESTIGATING, or RESOLVED.")
    with connect() as conn:
        cur = conn.execute("UPDATE alerts SET alert_status=? WHERE alert_id=?", (status, alert_id)); conn.commit()
    return cur.rowcount > 0


def update_analyst_notes(alert_id, notes):
    if not isinstance(notes, str): raise TypeError("Notes must be text.")
    if len(notes) > 5000: raise ValueError("Notes must be 5,000 characters or fewer.")
    with connect() as conn:
        cur = conn.execute("UPDATE alerts SET analyst_notes=? WHERE alert_id=?", (notes.strip(), alert_id)); conn.commit()
    return cur.rowcount > 0


def get_alert_statistics():
    alerts = get_all_alerts(limit=100000)
    counts = {s: sum(a.get("risk_level") == s for a in alerts) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    statuses = {s: sum(a.get("alert_status") == s for a in alerts) for s in ("NEW", "INVESTIGATING", "RESOLVED")}
    return {"total_alerts": len(alerts), "severity_distribution": counts, "status_distribution": statuses, "average_risk_score": round(sum(float(a.get("risk_score", 0)) for a in alerts) / len(alerts), 2) if alerts else 0}

init_db()
