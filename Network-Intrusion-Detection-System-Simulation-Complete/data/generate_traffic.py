from pathlib import Path
import random
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "network_traffic.csv"


def generate_dataset(rows: int = 6000, seed: int = 42) -> pd.DataFrame:
    """Generate safe, fictional network-flow records for offline IDS testing."""
    rng = random.Random(seed)
    scenarios = ["normal", "port_scan", "brute_force", "dos", "data_exfiltration", "malware_like"]
    weights = [0.68, 0.08, 0.08, 0.06, 0.05, 0.05]
    protocols = ["TCP", "UDP", "ICMP"]
    ports = [22, 25, 53, 80, 110, 143, 443, 3306, 8080, 8443, 3389, 445, 123]
    records = []
    for i in range(1, rows + 1):
        scenario = rng.choices(scenarios, weights=weights, k=1)[0]
        malicious = scenario != "normal"
        source_ip = f"10.0.{rng.randint(0, 3)}.{rng.randint(2, 254)}"
        destination_ip = f"10.0.{rng.randint(4, 7)}.{rng.randint(2, 254)}"
        protocol = rng.choices(protocols, weights=[0.62, 0.28, 0.10], k=1)[0]
        destination_port = rng.choice(ports)
        packet_count = rng.randint(2, 250)
        byte_count = packet_count * rng.randint(40, 900)
        duration = round(rng.uniform(0.1, 120.0), 2)
        failed = rng.randint(0, 3)
        unique_ports = rng.randint(1, 4)
        if scenario == "port_scan":
            unique_ports = rng.randint(15, 100); packet_count = rng.randint(80, 900); failed = rng.randint(3, 25)
        elif scenario == "brute_force":
            failed = rng.randint(10, 80); destination_port = rng.choice([22, 3389, 21, 25]); packet_count = rng.randint(50, 500)
        elif scenario == "dos":
            packet_count = rng.randint(1600, 5000); byte_count = packet_count * rng.randint(500, 1500); duration = round(rng.uniform(1, 90), 2)
        elif scenario == "data_exfiltration":
            byte_count = rng.randint(5_000_001, 15_000_000); packet_count = rng.randint(500, 1800); duration = round(rng.uniform(10, 600), 2)
        elif scenario == "malware_like":
            failed = rng.randint(5, 18); unique_ports = rng.randint(6, 20); duration = round(rng.uniform(100, 700), 2)
        # Dataset timestamps are synthetic and intentionally not tied to live traffic.
        minute_offset = rng.randint(0, 60 * 24 * 5)
        from datetime import datetime, timedelta
        timestamp = (datetime(2026, 9, 1) + timedelta(minutes=minute_offset)).isoformat(timespec="minutes")
        records.append({
            "flow_id": i, "timestamp": timestamp, "source_ip": source_ip,
            "destination_ip": destination_ip, "source_port": rng.randint(1024, 65535),
            "destination_port": destination_port, "protocol": protocol,
            "packet_count": packet_count, "byte_count": byte_count,
            "connection_duration": duration, "failed_connections": failed,
            "unique_destination_ports": unique_ports, "scenario": scenario,
            "label": "malicious" if malicious else "benign",
        })
    return pd.DataFrame(records)


if __name__ == "__main__":
    df = generate_dataset()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT, index=False)
    print(f"Created {len(df):,} synthetic flows: {OUTPUT}")
    print(df["label"].value_counts().to_string())
