from __future__ import annotations

import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from insider_threat_detection.detector import BehaviorProfiler
from insider_threat_detection.models import NetworkEvent, UserProfile


def classify_severity(score: float) -> str:
    if score >= 4.0:
        return "Critical"
    if score >= 3.0:
        return "High"
    if score >= 2.5:
        return "Medium"
    if score > 0:
        return "Low"
    return "Normal"


def parse_event(row: dict[str, str]) -> NetworkEvent:
    return NetworkEvent(
        timestamp=datetime.fromisoformat(row["timestamp"]),
        user_id=row["user_id"],
        source_ip=row["source_ip"],
        destination_ip=row["destination_ip"],
        protocol=row["protocol"],
        action=row["action"],
        bytes_sent=int(row["bytes_sent"]),
        bytes_received=int(row["bytes_received"]),
    )


def load_events(csv_path: Path) -> list[NetworkEvent]:
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    events: list[NetworkEvent] = []
    with csv_path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            try:
                if not row or any(row.get(field) in (None, "") for field in reader.fieldnames or []):
                    continue
                events.append(parse_event(row))
            except (KeyError, TypeError, ValueError):
                continue
    return events


def analyze_events(csv_path: Path) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    profiler = BehaviorProfiler()
    profiles: dict[str, UserProfile] = defaultdict(lambda: UserProfile(user_id="unknown"))
    scored_events: list[dict[str, object]] = []
    alerts: list[dict[str, str]] = []

    for event in load_events(csv_path):
        if event.user_id not in profiles:
            profiles[event.user_id] = UserProfile(user_id=event.user_id)

        profile = profiles[event.user_id]
        result = profiler.score_event(event, profile)
        reasons_text = ", ".join(result.reasons) if result.reasons else "normal activity"
        severity = classify_severity(result.score)

        scored_events.append(
            {
                "timestamp": event.timestamp.isoformat(),
                "user_id": event.user_id,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "protocol": event.protocol,
                "action": event.action,
                "bytes_sent": event.bytes_sent,
                "bytes_received": event.bytes_received,
                "score": result.score,
                "alert": result.alert,
                "severity": severity,
                "reasons": reasons_text,
            }
        )

        if result.alert:
            alerts.append(
                {
                    "timestamp": event.timestamp.isoformat(),
                    "user_id": event.user_id,
                    "score": f"{result.score:.2f}",
                    "severity": severity,
                    "reasons": reasons_text,
                }
            )
        profiler.update_profile(event, profile)

    return scored_events, alerts


def run_pipeline(csv_path: Path) -> list[dict[str, str]]:
    _, alerts = analyze_events(csv_path)
    return alerts


def main() -> None:
    csv_path = Path("data") / "network_events.csv"
    if not csv_path.exists():
        raise FileNotFoundError(
            "Expected sample data at data/network_events.csv. "
            "Run `python scripts/generate_sample_data.py` first."
        )

    alerts = run_pipeline(csv_path)
    print(f"Processed {csv_path}")
    print(f"Generated {len(alerts)} alerts")
    print("-" * 60)
    for alert in alerts[:15]:
        print(
            f"[ALERT] {alert['timestamp']} | {alert['user_id']} | "
            f"score={alert['score']} | {alert['reasons']}"
        )

    if len(alerts) > 15:
        print("-" * 60)
        print(f"... {len(alerts) - 15} more alerts not shown")


if __name__ == "__main__":
    main()
