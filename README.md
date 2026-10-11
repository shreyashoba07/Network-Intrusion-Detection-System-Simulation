# Network Intrusion Detection System (IDS) Simulation

A defensive, educational Network-Based Hybrid IDS built around **synthetic network-flow records**. It combines transparent signature rules, threshold-based anomaly detection, an optional trained Random Forest model, hybrid risk scoring, alert correlation, SQLite persistence, and a React SOC dashboard.

> **Safety and scope:** This project generates and analyzes fictional network-flow records only. It does not capture packets, scan hosts, send attack traffic, or connect to external target systems. All IP addresses in generated records use private `10.0.0.0/8`-style ranges.

## Features

- 6,000-record synthetic traffic generator with normal, port-scan, brute-force, DoS-like, data-transfer, and malware-like *simulated labels*.
- Signature rules and anomaly thresholds with explanations.
- Optional Random Forest classifier and a transparent fallback when no model has been trained.
- Weighted hybrid risk score: signatures 40%, anomalies 30%, ML probability 30%.
- FastAPI endpoints for health, analysis, alerts, analyst status/notes, correlations, statistics, and analytics.
- SQLite persistence for alerts and analyst workflow.
- React dashboard with KPI cards, traffic trend, severity/protocol/scenario charts, destination ports, top source IPs, searchable alert queue, and investigation drawer.
- Automated tests for detectors, risk scoring, correlation, analytics, and API endpoints.

## Architecture

```text
Synthetic Flow Dataset -> Signature Rules + Anomaly Checks + ML Model
                                         |                    |
                                         +---- Hybrid Risk ----+
                                                  |
                                           Alert + Correlation
                                                  |
                                              SQLite DB
                                                  |
                                    FastAPI -> React SOC Dashboard
```

## Requirements

- Windows 10/11 or macOS/Linux
- Python 3.10 or newer
- Node.js 20 or newer (recommended)
- VS Code is optional

## Run on Windows PowerShell

Open PowerShell in the project root (`Network-Intrusion-Detection-System-Simulation-Complete`). Run each command separately.

### 1. Create a virtual environment and install Python packages

```powershell
py -3 -m venv venv
.env\Scripts\python.exe -m pip install --upgrade pip
.env\Scripts\python.exe -m pip install -r requirements.txt
```

If `py -3` is unavailable but `python` works, use `python -m venv venv`. If neither command works, install Python from python.org and enable **Add Python to PATH**.

### 2. Generate the synthetic dataset

```powershell
.env\Scripts\python.exe data\generate_traffic.py
```

Expected: 6,000 synthetic flow records written to `data/network_traffic.csv`.

### 3. Train and evaluate the optional ML model

```powershell
.env\Scripts\python.exe -m ml.train_model
```

Metrics are written to `reports/ml_metrics.json`. The evaluation uses a held-out split from this synthetic dataset only. Perfect or high synthetic metrics must **not** be interpreted as real-world accuracy; scenario patterns may be easy to distinguish and the data is not representative of production networks.

### 4. Start the backend

In terminal 1, from the project root:

```powershell
.env\Scripts\python.exe -m uvicorn backend.main:app --reload --port 8000
```

Open `http://127.0.0.1:8000/health` and `http://127.0.0.1:8000/docs` to check the API.

### 5. Seed alerts from the synthetic dataset (optional but recommended)

Keep the backend running. Open terminal 2 in the project root and run:

```powershell
.env\Scripts\python.exe -m src.process_dataset
```

This analyzes the dataset and stores detected alerts in `backend/ids.sqlite3`. It can take a little while. Run it again to update/recreate the alert records; existing analyst notes/status are not guaranteed to be preserved if you delete the SQLite database.

### 6. Start the React dashboard

Open terminal 3 in the project root:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173/`. Keep the backend and Vite terminals running while using the dashboard.

## Useful API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Service status |
| GET | `/health` | Health check |
| GET | `/docs` | Interactive API docs |
| GET | `/analytics` | Dataset and alert analytics |
| GET | `/stats` | Alert severity/status counts |
| GET | `/alerts` | Alert queue; supports `limit`, `severity`, `status`, `search` |
| GET | `/alerts/{alert_id}` | One alert |
| POST | `/analyze` | Analyze one submitted synthetic flow |
| POST | `/simulate?count=5` | Analyze a sample of synthetic dataset rows |
| GET | `/correlations?time_window_seconds=300` | Group related alerts |
| PUT | `/alerts/{alert_id}/status` | Set NEW, INVESTIGATING, or RESOLVED |
| PUT | `/alerts/{alert_id}/notes` | Save analyst notes |

## Run tests

From the project root:

```powershell
.env\Scripts\python.exe -m pytest -q
```

## Detection design

- **Signature-based:** fixed thresholds for high unique-port diversity, failed connections, packet count, and byte count. Transparent and explainable, but threshold rules can miss new patterns.
- **Anomaly-based:** separate thresholds for unusually high packets/bytes, failed connections, destination-port diversity, and connection duration. Thresholds are illustrative, not calibrated to a real network.
- **Machine learning:** Random Forest uses numeric flow features. The model is trained and evaluated on generated records. Data leakage and overly clean synthetic labels are important limitations to discuss.
- **Hybrid score:** `0.40 × signature score + 0.30 × anomaly score + 0.30 × ML malicious probability`. Signature/anomaly component scores increase by 25 points per matching rule, capped at 100. Risk bands: LOW <30, MEDIUM 30–59.99, HIGH 60–79.99, CRITICAL ≥80.
- **Correlation:** groups alerts by source IP and detector/rule type inside a configured time window. Correlation is an analyst aid, not proof that events share a cause.

## False positives and false negatives

A benign flow may exceed a threshold and produce a false positive. A suspicious flow may remain below every threshold and produce a false negative. Production use would require representative labeled data, calibrated thresholds, drift monitoring, analyst feedback, and testing on independent networks. This simulation is not a production IDS.

## IDS vs IPS

An IDS detects and reports potential activity. An IPS attempts to prevent/block activity. This project is **detection-only**; it does not block or modify network traffic.

## High-level MITRE ATT&CK concepts

Scenario labels are inspired by broad behavior categories such as discovery/port scanning, credential access/brute force, denial-of-service-like activity, and exfiltration-like transfer. These are educational analogies, not validated ATT&CK technique detections or official mappings.

## Privacy and security

- Synthetic data only; no packet capture or external scanning.
- SQLite is local and intended for a single-user demo.
- Do not put real personal, corporate, or sensitive network data in public repositories.
- Do not expose the development server to the public internet.
- CORS is restricted to the local Vite development origins.

## Suggested GitHub screenshots

Capture: dashboard overview; traffic charts; alert queue; one investigation drawer showing rule/anomaly evidence; `/docs` API page; test output; `reports/ml_metrics.json`. Never include private data or secrets.

## Resume bullet

Built a defensive Network Intrusion Detection System simulation using Python, FastAPI, SQLite, React, and scikit-learn; implemented synthetic flow generation, signature/anomaly detection, hybrid risk scoring, alert correlation, analyst workflow, and SOC-style visual analytics.

## Future improvements

- Evaluate on a separate, responsibly obtained benchmark dataset.
- Add configurable thresholds and model calibration.
- Add pagination and server-side alert filtering for large alert volumes.
- Add streaming simulation, authentication, and role-based access.
- Add validated SIEM export schemas and more robust audit logging.
