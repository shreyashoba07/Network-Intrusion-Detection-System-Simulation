# Project Report: Network Intrusion Detection System Simulation

## Abstract
This project implements a defensive, offline Network Intrusion Detection System (IDS) demonstration using generated network-flow records. A hybrid pipeline combines rule-based signature checks, threshold-based anomaly detection, and an optional Random Forest classifier. A weighted risk score is attached to detections and stored in SQLite. A FastAPI service exposes alert and analytics endpoints, while a React SOC-style dashboard presents summary metrics, visualizations, and analyst investigation controls.

## Problem statement
Learning network defense is difficult without a safe environment that produces explainable detections. This project creates a synthetic dataset and a local-only workflow to demonstrate detection concepts without scanning real systems or generating attack traffic.

## Objectives
1. Generate a repeatable synthetic network-flow dataset.
2. Detect illustrative suspicious patterns with signatures and anomaly thresholds.
3. Train and evaluate an optional classifier on synthetic data.
4. Combine detector outputs into a hybrid risk score.
5. Store alerts and support analyst notes/status.
6. Present analytics in a SOC-style dashboard.

## Methodology
Synthetic rows are generated with flow metadata and scenario labels. Numeric features are used by the optional Random Forest model. Signature and anomaly modules run independently. The risk engine weights the signature score at 40%, anomaly score at 30%, and model malicious probability at 30%. Alerts are persisted in SQLite and summarized through FastAPI. The frontend polls the API every 30 seconds and supports severity/status filters and alert investigation.

## Tools
Python, pandas, scikit-learn, FastAPI, SQLite, React, Vite, Recharts, pytest.

## Results and evaluation
Run `python -m ml.train_model` to produce `reports/ml_metrics.json` with accuracy, precision, recall, F1, and confusion matrix. Report the actual generated values in a submission. Because the data is synthetic and scenario-derived, these metrics indicate only performance on that generated split; they do not demonstrate real-world detection performance.

## Limitations
Thresholds are illustrative. Generated labels can be easier to classify than real activity. Source IPs and timestamps are synthetic. The project does not capture packets, detect encrypted payload contents, block traffic, or integrate with a production SIEM. Correlation is heuristic. Production use would require privacy review, independent evaluation, monitoring, access control, and operational validation.

## Conclusion
The project demonstrates an end-to-end defensive detection workflow from synthetic flow generation to analyst-oriented dashboarding. It is appropriate as a learning and portfolio simulation, not as a production security control.
