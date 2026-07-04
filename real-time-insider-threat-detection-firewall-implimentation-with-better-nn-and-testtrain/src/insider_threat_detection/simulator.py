from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


FIELDNAMES = [
    "timestamp",
    "user_id",
    "source_ip",
    "destination_ip",
    "protocol",
    "action",
    "bytes_sent",
    "bytes_received",
]


def _resolve_last_timestamp(existing_rows: list[dict[str, str]]) -> datetime:
    now = datetime.now().replace(second=0, microsecond=0)
    if existing_rows:
        latest_timestamp = max(datetime.fromisoformat(str(row["timestamp"])) for row in existing_rows)
        return min(latest_timestamp, now - timedelta(minutes=5))
    return now - timedelta(minutes=5)


def _risky_user_id_for_batch(user_count: int, batch_index: int) -> str:
    return f"user_{(batch_index % user_count) + 1}"


def _batch_index_from_existing_rows(existing_rows: list[dict[str, str]], batch_size: int) -> int:
    if not existing_rows or batch_size <= 0:
        return 0
    return len(existing_rows) // batch_size


def _build_user_context(user_count: int) -> list[dict[str, object]]:
    users = [f"user_{index + 1}" for index in range(user_count)]
    destinations = [f"10.0.0.{index}" for index in range(10, 25)]
    source_ranges = [f"192.168.1.{index}" for index in range(2, 15)]
    contexts: list[dict[str, object]] = []

    for user in users:
        contexts.append(
            {
                "user_id": user,
                "preferred_hour": random.randint(8, 17),
                "normal_destinations": random.sample(destinations, 4),
                "normal_source": random.choice(source_ranges),
            }
        )

    return contexts


def _read_existing_rows(csv_path: Path) -> list[dict[str, str]]:
    if not csv_path.exists():
        return []

    with csv_path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return list(reader)


def _write_rows(output_path: Path, rows: list[dict[str, str | int]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def _append_rows(output_path: Path, rows: list[dict[str, str | int]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = output_path.exists()
    with output_path.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)


def generate_sample_events_csv(
    output_path: Path,
    user_count: int = 5,
    events_per_user: int = 60,
    seed: int = 7,
) -> None:
    random.seed(seed)
    protocols = ["TCP", "UDP", "HTTPS", "DNS"]
    actions = ["login", "file_access", "email", "database_query"]
    contexts = _build_user_context(user_count)

    now = datetime.now().replace(second=0, microsecond=0)
    total_events = user_count * events_per_user
    total_duration_minutes = max(total_events - 1, 0) * 20
    start_time = now - timedelta(minutes=total_duration_minutes)
    rows: list[dict[str, str | int]] = []

    for context in contexts:
        user_id = str(context["user_id"])
        preferred_hour = int(context["preferred_hour"])
        normal_destinations = list(context["normal_destinations"])
        normal_source = str(context["normal_source"])
        suspicious_count = min(6, events_per_user)
        suspicious_start = events_per_user - suspicious_count

        for event_index in range(events_per_user):
            timestamp = start_time + timedelta(minutes=20 * event_index) + timedelta(
                hours=max(0, preferred_hour - 8)
            )
            suspicious = event_index >= suspicious_start and user_id == str(contexts[-1]["user_id"])
            if suspicious:
                # Force late-night, repeated activity for the risky user so the
                # demo reliably produces multiple critical insider-threat alerts.
                suspicious_hours = [2, 2, 2, 2, 2, 3]
                suspicious_minutes = [0, 10, 20, 30, 40, 0]
                suspicious_index = event_index - suspicious_start
                timestamp = timestamp.replace(
                    hour=suspicious_hours[suspicious_index],
                    minute=suspicious_minutes[suspicious_index],
                )
            else:
                timestamp = timestamp.replace(hour=min(23, max(0, preferred_hour + random.randint(-2, 2))))

            row = {
                "timestamp": timestamp.isoformat(),
                "user_id": user_id,
                "source_ip": (
                    f"172.16.99.{150 + suspicious_index}"
                    if suspicious
                    else normal_source
                ),
                "destination_ip": (
                    f"10.0.0.{20 + suspicious_index}"
                    if suspicious
                    else random.choice(normal_destinations)
                ),
                "protocol": random.choice(protocols),
                "action": random.choice(actions),
                "bytes_sent": (
                    22000 + suspicious_index * 2500
                    if suspicious
                    else random.randint(400, 4000)
                ),
                "bytes_received": (
                    12000 + suspicious_index * 1800
                    if suspicious
                    else random.randint(300, 2500)
                ),
            }
            rows.append(row)

    rows.sort(key=lambda item: item["timestamp"])
    for row in rows:
        row_timestamp = datetime.fromisoformat(str(row["timestamp"]))
        if row_timestamp > now:
            row["timestamp"] = now.isoformat()
    _write_rows(output_path, rows)


def append_sample_events_csv(
    output_path: Path,
    user_count: int = 6,
    events_per_user: int = 80,
    seed: int | None = None,
) -> None:
    if seed is not None:
        random.seed(seed)

    protocols = ["TCP", "UDP", "HTTPS", "DNS"]
    actions = ["login", "file_access", "email", "database_query"]
    existing_rows = _read_existing_rows(output_path)
    start_time = _resolve_last_timestamp(existing_rows)
    now = datetime.now().replace(second=0, microsecond=0)
    batch_index = _batch_index_from_existing_rows(existing_rows, user_count * events_per_user)
    risky_user_id = _risky_user_id_for_batch(user_count, batch_index)
    contexts = _build_user_context(user_count)
    rows: list[dict[str, str | int]] = []

    for context_index, context in enumerate(contexts):
        user_id = str(context["user_id"])
        preferred_hour = int(context["preferred_hour"])
        normal_destinations = list(context["normal_destinations"])
        normal_source = str(context["normal_source"])
        suspicious_count = min(6, events_per_user)
        suspicious_start = events_per_user - suspicious_count

        for event_index in range(events_per_user):
            timestamp = start_time + timedelta(
                minutes=20 * (context_index * events_per_user + event_index + 1)
            )
            suspicious = event_index >= suspicious_start and user_id == risky_user_id
            suspicious_index = max(0, event_index - suspicious_start)
            if suspicious:
                suspicious_hour = 1 + ((batch_index + suspicious_index) % 4)
                suspicious_minute = (suspicious_index * 10) % 60
                timestamp = timestamp.replace(hour=suspicious_hour, minute=suspicious_minute)
            else:
                timestamp = timestamp.replace(
                    hour=min(23, max(0, preferred_hour + random.randint(-2, 2)))
                )
            timestamp = min(timestamp, now)

            rows.append(
                {
                    "timestamp": timestamp.isoformat(),
                    "user_id": user_id,
                    "source_ip": f"172.16.99.{150 + batch_index + suspicious_index}" if suspicious else normal_source,
                    "destination_ip": f"10.0.0.{20 + ((batch_index + suspicious_index) % 5)}"
                    if suspicious
                    else random.choice(normal_destinations),
                    "protocol": random.choice(protocols),
                    "action": random.choice(actions),
                    "bytes_sent": 22000 + suspicious_index * 2500 + batch_index * 400
                    if suspicious
                    else random.randint(400, 4000),
                    "bytes_received": 12000 + suspicious_index * 1800 + batch_index * 250
                    if suspicious
                    else random.randint(300, 2500),
                }
            )

    rows.sort(key=lambda item: item["timestamp"])
    _append_rows(output_path, rows)


def append_live_events_csv(
    output_path: Path,
    user_count: int = 6,
    events_to_add: int = 8,
    seed: int | None = None,
) -> None:
    if seed is not None:
        random.seed(seed)

    protocols = ["TCP", "UDP", "HTTPS", "DNS"]
    actions = ["login", "file_access", "email", "database_query"]
    destinations = [f"10.0.0.{index}" for index in range(10, 25)]
    existing_rows = _read_existing_rows(output_path)
    contexts = _build_user_context(user_count)
    last_timestamp = _resolve_last_timestamp(existing_rows)
    now = datetime.now().replace(second=0, microsecond=0)

    new_rows: list[dict[str, str | int]] = []
    batch_index = _batch_index_from_existing_rows(existing_rows, max(events_to_add, 1))
    risky_user_id = _risky_user_id_for_batch(user_count, batch_index)

    for event_index in range(events_to_add):
        context = contexts[event_index % len(contexts)]
        user_id = str(context["user_id"])
        preferred_hour = int(context["preferred_hour"])
        normal_destinations = list(context["normal_destinations"])
        normal_source = str(context["normal_source"])

        timestamp = last_timestamp + timedelta(minutes=5 * (event_index + 1))
        suspicious = user_id == risky_user_id and random.random() < 0.55
        if suspicious:
            # Use repeated off-hours activity to simulate an active insider
            # exfiltration session and trigger critical-level alerts.
            suspicious_hour = 1 + ((batch_index + event_index) % 4)
            timestamp = timestamp.replace(hour=suspicious_hour)
        elif event_index % 3 == 0:
            timestamp = timestamp.replace(hour=min(23, max(0, preferred_hour + random.randint(-2, 2))))
        timestamp = min(timestamp, now)

        row = {
            "timestamp": timestamp.isoformat(),
            "user_id": user_id,
            "source_ip": f"172.16.99.{random.randint(100, 220)}" if suspicious else normal_source,
            "destination_ip": random.choice(destinations) if suspicious else random.choice(normal_destinations),
            "protocol": random.choice(protocols),
            "action": random.choice(actions),
            "bytes_sent": random.randint(16000, 32000) if suspicious else random.randint(500, 4500),
            "bytes_received": random.randint(9000, 22000) if suspicious else random.randint(350, 2800),
        }
        new_rows.append(row)

    _append_rows(output_path, new_rows)
