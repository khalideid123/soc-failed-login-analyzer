from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

FAILED = "FAILED"
SUCCESS = "SUCCESS"
DEFAULT_THRESHOLD = 5


def load_events(csv_path: Path) -> list[dict[str, str]]:
    """Load authentication events from a CSV file."""
    with csv_path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        required = {"timestamp", "username", "source_ip", "status"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            missing = required - set(reader.fieldnames or [])
            raise ValueError(f"Missing required CSV columns: {sorted(missing)}")
        return [dict(row) for row in reader]


def analyze_events(events: Iterable[dict[str, str]], threshold: int = DEFAULT_THRESHOLD) -> list[dict]:
    """Return alerts for source IPs meeting the failed-login threshold."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    activity = defaultdict(lambda: {
        "failed_attempts": 0,
        "successful_attempts": 0,
        "users": set(),
        "first_seen": None,
        "last_seen": None,
        "success_after_failures": False,
    })

    for event in events:
        ip = event["source_ip"].strip()
        username = event["username"].strip()
        status = event["status"].strip().upper()
        timestamp = event["timestamp"].strip()
        record = activity[ip]
        record["users"].add(username)
        if record["first_seen"] is None:
            record["first_seen"] = timestamp
        record["last_seen"] = timestamp

        if status == FAILED:
            record["failed_attempts"] += 1
        elif status == SUCCESS:
            record["successful_attempts"] += 1
            if record["failed_attempts"] > 0:
                record["success_after_failures"] = True

    alerts = []
    for ip, record in activity.items():
        if record["failed_attempts"] >= threshold:
            severity = "high" if record["success_after_failures"] else "medium"
            alerts.append({
                "source_ip": ip,
                "severity": severity,
                "failed_attempts": record["failed_attempts"],
                "successful_attempts": record["successful_attempts"],
                "users": sorted(record["users"]),
                "first_seen": record["first_seen"],
                "last_seen": record["last_seen"],
                "success_after_failures": record["success_after_failures"],
                "reason": f"{record['failed_attempts']} failed login attempts met the detection threshold of {threshold}.",
            })

    return sorted(alerts, key=lambda alert: (-alert["failed_attempts"], alert["source_ip"]))


def save_alerts(alerts: list[dict], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=2)


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    input_path = project_root / "data" / "auth_logs.csv"
    output_path = project_root / "output" / "alerts.json"
    events = load_events(input_path)
    alerts = analyze_events(events)
    save_alerts(alerts, output_path)

    print(f"Analyzed {len(events)} authentication events.")
    print(f"Generated {len(alerts)} alert(s).")
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['source_ip']} - {alert['failed_attempts']} failed attempts")


if __name__ == "__main__":
    main()
