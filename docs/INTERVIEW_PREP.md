# Interview Preparation

**What did you build?** A defensive, local Network IDS simulation that analyzes synthetic flow records using signature rules, anomaly thresholds, and an optional Random Forest model. It stores alerts in SQLite and exposes data through FastAPI to a React dashboard.

**Why hybrid detection?** Signatures are explainable but fixed; anomaly rules catch unusual metrics; ML can learn combinations of numeric features. Combining them provides a teaching example, although it does not guarantee better real-world accuracy.

**How is risk calculated?** Signature score contributes 40%, anomaly score 30%, and ML malicious probability 30%. The component scores are capped at 100 and the final score maps to LOW/MEDIUM/HIGH/CRITICAL bands.

**What is a false positive?** Benign behavior flagged as suspicious. What is a false negative? Suspicious behavior missed by the detector.

**Why synthetic data?** It provides a safe, repeatable environment without capturing traffic or interacting with real targets. Its limitation is poor representation of production networks.

**What is the difference between IDS and IPS?** IDS detects and alerts; IPS attempts to block/prevent. This project is detection-only.

**What does SQLite do?** It persistently stores alerts, detector evidence, status, and analyst notes in a local database.

**How would you improve it?** Evaluate on an independent benchmark, calibrate thresholds, measure false-positive rates, add authentication/audit logs, improve pagination, and validate integrations before production use.

**Be transparent:** Never present synthetic split metrics as real-world performance. Explain that the project is an educational prototype.
