from __future__ import annotations

import csv
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from insider_threat_detection.ai_firewall_advisor import recommend_firewall_action
from insider_threat_detection.firewall import (
    approve_recommendation,
    deactivate_rule,
    execute_firewall_unblock,
    list_recommendations,
    list_rules,
    make_event_key,
    reject_recommendation,
    RULE_FIELDS,
    upsert_recommendations,
    _write_csv,
)
from insider_threat_detection.pipeline import analyze_events
from insider_threat_detection.simulator import (
    FIELDNAMES,
    append_live_events_csv,
    append_sample_events_csv,
    generate_sample_events_csv,
)


DATA_PATH = PROJECT_ROOT / "data" / "network_events.csv"
RECOMMENDATIONS_PATH = PROJECT_ROOT / "data" / "firewall_recommendations.csv"
RULES_PATH = PROJECT_ROOT / "data" / "firewall_rules.csv"

collector_thread: threading.Thread | None = None
collector_stop_event: threading.Event | None = None
collector_config: dict[str, int] = {"interval_seconds": 5, "events_per_batch": 6}
expiration_thread: threading.Thread | None = None
expiration_stop_event: threading.Event | None = None


class EventIn(BaseModel):
    timestamp: str
    user_id: str
    source_ip: str
    destination_ip: str
    protocol: str
    action: str
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)


class EventsPayload(BaseModel):
    events: list[EventIn]


class CollectorStartPayload(BaseModel):
    interval_seconds: int = Field(default=5, ge=2, le=60)
    events_per_batch: int = Field(default=6, ge=1, le=50)


class RecommendationActionPayload(BaseModel):
    recommendation_id: str


class RuleActionPayload(BaseModel):
    rule_id: str


app = FastAPI(title="Insider Threat Web API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def ensure_data_file() -> None:
    if not DATA_PATH.exists() or DATA_PATH.stat().st_size == 0:
        generate_sample_events_csv(DATA_PATH, user_count=6, events_per_user=80)


def append_events(rows: list[dict[str, Any]]) -> int:
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    file_exists = DATA_PATH.exists() and DATA_PATH.stat().st_size > 0
    with DATA_PATH.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        accepted = 0
        for row in rows:
            if all(row.get(field) not in (None, "") for field in FIELDNAMES):
                writer.writerow({field: row[field] for field in FIELDNAMES})
                accepted += 1
    return accepted


def dashboard_data() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ensure_data_file()
    scored_events, alerts = analyze_events(DATA_PATH)
    return scored_events, alerts


def sync_firewall_recommendations() -> list[dict[str, str]]:
    scored_events, _ = dashboard_data()
    new_recommendations: list[dict[str, Any]] = []
    for event in scored_events:
        is_test_site_access = "test_site_access" in str(event.get("action", "")).lower()
        if not event.get("alert") and not is_test_site_access:
            continue
        recommendation = recommend_firewall_action(event)
        new_recommendations.append(
            {
                "event_key": make_event_key(event),
                "timestamp": event["timestamp"],
                "user_id": event["user_id"],
                "source_ip": event["source_ip"],
                "destination_ip": event["destination_ip"],
                "protocol": event["protocol"],
                "port": recommendation.port or "",
                "severity": event["severity"],
                "score": event["score"],
                "reasons": event["reasons"],
                "ai_action": recommendation.ai_action,
                "target_type": recommendation.target_type,
                "target_value": recommendation.target_value,
                "duration_minutes": recommendation.duration_minutes,
                "confidence": recommendation.confidence,
                "explanation": recommendation.explanation,
                "status": "pending",
            }
        )
    return upsert_recommendations(RECOMMENDATIONS_PATH, new_recommendations)


def build_summary(events: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    alert_counts_by_user: dict[str, int] = {}
    traffic_by_hour: dict[str, dict[str, int]] = {}
    score_by_hour: dict[str, list[float]] = {}
    reason_counts: dict[str, int] = {}

    for event in events:
        hour = str(event["timestamp"][:13])
        traffic = traffic_by_hour.setdefault(hour, {"bytes_sent": 0, "bytes_received": 0})
        traffic["bytes_sent"] += int(event["bytes_sent"])
        traffic["bytes_received"] += int(event["bytes_received"])
        score_by_hour.setdefault(hour, []).append(float(event["score"]))
        if event.get("alert"):
            alert_counts_by_user[event["user_id"]] = alert_counts_by_user.get(event["user_id"], 0) + 1

    for alert in alerts:
        severity = str(alert["severity"])
        if severity in severity_counts:
            severity_counts[severity] += 1
        for reason in str(alert["reasons"]).split(", "):
            if reason and reason != "normal activity":
                reason_counts[reason] = reason_counts.get(reason, 0) + 1

    average_score_by_hour = [
        {"hour": hour, "score": round(sum(scores) / len(scores), 2)}
        for hour, scores in sorted(score_by_hour.items())
    ]
    traffic_series = [
        {"hour": hour, **values}
        for hour, values in sorted(traffic_by_hour.items())
    ]
    alert_rate = (len(alerts) / len(events) * 100) if events else 0.0

    return {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "alert_rate": round(alert_rate, 1),
        "average_score": round(sum(float(event["score"]) for event in events) / len(events), 2) if events else 0,
        "critical_count": severity_counts["Critical"],
        "severity_counts": severity_counts,
        "alert_counts_by_user": [
            {"user_id": user_id, "alerts": count}
            for user_id, count in sorted(alert_counts_by_user.items(), key=lambda item: item[1], reverse=True)
        ],
        "traffic_by_hour": traffic_series[-24:],
        "score_by_hour": average_score_by_hour[-24:],
        "reason_counts": [
            {"reason": reason, "count": count}
            for reason, count in sorted(reason_counts.items(), key=lambda item: item[1], reverse=True)
        ],
    }


def collector_loop(stop_event: threading.Event, interval_seconds: int, events_per_batch: int) -> None:
    ensure_data_file()
    while not stop_event.is_set():
        append_live_events_csv(DATA_PATH, user_count=6, events_to_add=events_per_batch)
        sync_firewall_recommendations()
        stop_event.wait(interval_seconds)


def expire_firewall_rules_once() -> int:
    rules = list_rules(RULES_PATH)
    now = datetime.now()
    expired_count = 0

    for rule in rules:
        if rule.get("status") != "active":
            continue

        try:
            created_at = datetime.fromisoformat(rule["created_at"])
            duration_minutes = int(float(rule.get("duration_minutes") or 0))
        except (KeyError, TypeError, ValueError):
            continue

        if duration_minutes <= 0:
            continue
        if now < created_at + timedelta(minutes=duration_minutes):
            continue

        execute_firewall_unblock(rule.get("source_ip", ""), rule.get("port", ""))
        rule["status"] = "inactive"
        expired_count += 1

    if expired_count:
        _write_csv(RULES_PATH, RULE_FIELDS, rules)
    return expired_count


def expiration_loop(stop_event: threading.Event, interval_seconds: int = 60) -> None:
    while not stop_event.is_set():
        expire_firewall_rules_once()
        stop_event.wait(interval_seconds)


@app.on_event("startup")
def start_expiration_worker() -> None:
    global expiration_stop_event, expiration_thread
    if expiration_thread is not None and expiration_thread.is_alive():
        return
    expiration_stop_event = threading.Event()
    expiration_thread = threading.Thread(
        target=expiration_loop,
        args=(expiration_stop_event,),
        daemon=True,
        name="firewall-rule-expiration",
    )
    expiration_thread.start()


@app.on_event("shutdown")
def stop_expiration_worker() -> None:
    if expiration_stop_event is not None:
        expiration_stop_event.set()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/events")
def events() -> dict[str, Any]:
    scored_events, _ = dashboard_data()
    return {"events": scored_events}


@app.post("/api/events")
def receive_events(payload: EventsPayload) -> dict[str, int]:
    accepted = append_events([event.model_dump() for event in payload.events])
    sync_firewall_recommendations()
    return {"accepted": accepted}


@app.get("/api/alerts")
def alerts() -> dict[str, Any]:
    _, alert_rows = dashboard_data()
    return {"alerts": alert_rows}


@app.get("/api/summary")
def summary() -> dict[str, Any]:
    scored_events, alert_rows = dashboard_data()
    sync_firewall_recommendations()
    return build_summary(scored_events, alert_rows)


@app.post("/api/simulate/live")
def simulate_live(payload: CollectorStartPayload) -> dict[str, str]:
    ensure_data_file()
    append_live_events_csv(DATA_PATH, user_count=6, events_to_add=payload.events_per_batch)
    sync_firewall_recommendations()
    return {"status": "appended"}


@app.post("/api/simulate/sample")
def simulate_sample() -> dict[str, str]:
    ensure_data_file()
    append_sample_events_csv(DATA_PATH, user_count=6, events_per_user=80)
    sync_firewall_recommendations()
    return {"status": "appended"}


@app.get("/api/firewall/recommendations")
def firewall_recommendations() -> dict[str, Any]:
    return {"recommendations": sync_firewall_recommendations()}


@app.get("/api/firewall/rules")
def firewall_rules() -> dict[str, Any]:
    expire_firewall_rules_once()
    return {"rules": list_rules(RULES_PATH)}


@app.post("/api/firewall/approve")
def approve_firewall(payload: RecommendationActionPayload) -> dict[str, Any]:
    result = approve_recommendation(RECOMMENDATIONS_PATH, RULES_PATH, payload.recommendation_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return {"result": result}


@app.post("/api/firewall/reject")
def reject_firewall(payload: RecommendationActionPayload) -> dict[str, Any]:
    result = reject_recommendation(RECOMMENDATIONS_PATH, payload.recommendation_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return {"result": result}


@app.post("/api/firewall/unblock")
def unblock_firewall(payload: RuleActionPayload) -> dict[str, Any]:
    result = deactivate_rule(RULES_PATH, payload.rule_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"result": result}


@app.post("/api/collector/start")
def start_collector(payload: CollectorStartPayload) -> dict[str, Any]:
    global collector_config, collector_stop_event, collector_thread
    if collector_thread is not None and collector_thread.is_alive():
        return {"running": True, **collector_config}

    collector_config = {
        "interval_seconds": payload.interval_seconds,
        "events_per_batch": payload.events_per_batch,
    }
    collector_stop_event = threading.Event()
    collector_thread = threading.Thread(
        target=collector_loop,
        args=(collector_stop_event, payload.interval_seconds, payload.events_per_batch),
        daemon=True,
        name="simulated-insider-threat-collector",
    )
    collector_thread.start()
    return {"running": True, **collector_config}


@app.post("/api/collector/stop")
def stop_collector() -> dict[str, Any]:
    global collector_stop_event
    if collector_stop_event is not None:
        collector_stop_event.set()
    return {"running": False}


@app.get("/api/collector/status")
def collector_status() -> dict[str, Any]:
    return {
        "running": collector_thread is not None and collector_thread.is_alive(),
        **collector_config,
    }
