from __future__ import annotations

import pickle
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np


ACTION_ALLOW = "allow"
ACTION_MONITOR = "monitor"
ACTION_BLOCK = "block"
ACTION_QUARANTINE = "quarantine"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "models" / "firewall_nn.keras"
PREPROCESSOR_PATH = PROJECT_ROOT / "models" / "firewall_preprocessor.pkl"
_NN_CACHE: tuple[Any, dict[str, Any]] | None = None


@dataclass(frozen=True)
class FirewallRecommendation:
    ai_action: str
    target_type: str
    target_value: str
    source_ip: str
    destination_ip: str
    protocol: str
    port: int | None
    duration_minutes: int
    confidence: float
    explanation: str


def _text(value: Any) -> str:
    return str(value or "")


def _score(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _infer_port(protocol: str, action: str) -> int | None:
    normalized = f"{protocol} {action}".lower()
    port_match = re.search(r"(?:port[_=\s-]?)(\d{1,5})", normalized)
    if port_match:
        return int(port_match.group(1))
    if "ssh" in normalized:
        return 22
    if "telnet" in normalized:
        return 23
    if "https" in normalized:
        return 443
    if "http" in normalized:
        return 80
    if "dns" in normalized:
        return 53
    return None


def _has_reason(reasons: str, phrase: str) -> bool:
    return phrase in reasons.lower()


def _to_dense(matrix: object) -> np.ndarray:
    if hasattr(matrix, "toarray"):
        matrix = matrix.toarray()
    return np.asarray(matrix, dtype=np.float32)


def _load_nn_assets() -> tuple[Any, dict[str, Any]] | None:
    global _NN_CACHE
    if _NN_CACHE is not None:
        return _NN_CACHE
    if not MODEL_PATH.exists() or not PREPROCESSOR_PATH.exists():
        return None

    try:
        import tensorflow as tf

        model = tf.keras.models.load_model(MODEL_PATH)
        with PREPROCESSOR_PATH.open("rb") as file:
            metadata = pickle.load(file)
    except Exception:
        return None

    _NN_CACHE = (model, metadata)
    return _NN_CACHE


def _zeek_like_row(alert: dict[str, Any], hour: int) -> dict[str, Any]:
    port = _infer_port(_text(alert.get("protocol")), _text(alert.get("action"))) or 0
    src_bytes = _score(alert.get("bytes_sent"))
    dst_bytes = _score(alert.get("bytes_received"))
    total_bytes = src_bytes + dst_bytes
    src_pkts = max(1.0, src_bytes / 1000.0)
    dst_pkts = max(1.0, dst_bytes / 1000.0)
    total_pkts = src_pkts + dst_pkts
    protocol = _text(alert.get("protocol")).lower() or "tcp"
    return {
        "src_ip": _text(alert.get("source_ip")),
        "dst_ip": _text(alert.get("destination_ip")),
        "proto": "tcp" if protocol == "http" else protocol,
        "service": protocol,
        "conn_state": "SF",
        "http_method": "GET" if "test_site_access" in _text(alert.get("action")).lower() else "",
        "ssl_version": "",
        "ssl_cipher": "",
        "http_version": "1.1" if protocol == "http" else "",
        "http_orig_mime_types": "",
        "http_resp_mime_types": "",
        "weird_notice": "",
        "src_port": 0,
        "dst_port": port,
        "duration": 0.0,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "missed_bytes": 0,
        "src_pkts": src_pkts,
        "dst_pkts": dst_pkts,
        "src_ip_bytes": src_bytes,
        "dst_ip_bytes": dst_bytes,
        "dns_qclass": 0,
        "dns_qtype": 0,
        "dns_rcode": 0,
        "http_trans_depth": 1 if protocol == "http" else 0,
        "http_request_body_len": 0,
        "http_response_body_len": dst_bytes,
        "http_status_code": 200,
        "total_bytes": total_bytes,
        "total_pkts": total_pkts,
        "byte_ratio": src_bytes / (dst_bytes + 1.0),
        "pkt_ratio": src_pkts / (dst_pkts + 1.0),
        "bytes_per_packet": total_bytes / (total_pkts + 1.0),
        "dns_query_length": 0,
        "http_uri_length": 1 if protocol == "http" else 0,
        "user_agent_length": 0,
        "dns_AA": 0,
        "dns_RD": 0,
        "dns_RA": 0,
        "dns_rejected": 0,
        "ssl_resumed": 0,
        "ssl_established": 0,
        "has_dns_query": 0,
        "has_ssl_subject": 0,
        "has_ssl_issuer": 0,
        "has_http_uri": 1 if protocol == "http" else 0,
        "has_user_agent": 0,
        "has_weird_name": 0,
        "has_weird_addl": 0,
        "is_common_dst_port": int(port in {22, 53, 80, 443, 8080}),
        "is_privileged_dst_port": int(0 < port < 1024),
        "hour": hour,
    }


def _nn_action(alert: dict[str, Any]) -> tuple[str, float] | None:
    assets = _load_nn_assets()
    if assets is None:
        return None

    try:
        import pandas as pd

        model, metadata = assets
        reasons = _text(alert.get("reasons"))
        timestamp = pd.to_datetime(_text(alert.get("timestamp")), errors="coerce")
        hour = int(timestamp.hour) if not pd.isna(timestamp) else 0
        if metadata.get("model_type") == "zeek_embedding_autoencoder":
            row = pd.DataFrame([_zeek_like_row(alert, hour)])
        else:
            row = pd.DataFrame(
                [
                    {
                        "user_id": _text(alert.get("user_id")),
                        "source_ip": _text(alert.get("source_ip")),
                        "destination_ip": _text(alert.get("destination_ip")),
                        "protocol": _text(alert.get("protocol")),
                        "action": _text(alert.get("action")),
                        "severity": _text(alert.get("severity")),
                        "hour": hour,
                        "bytes_sent": _score(alert.get("bytes_sent")),
                        "bytes_received": _score(alert.get("bytes_received")),
                        "score": _score(alert.get("score")),
                        "has_unusual_hour": int(_has_reason(reasons, "unusual access hour")),
                        "has_new_source_ip": int(_has_reason(reasons, "new source ip")),
                        "has_new_destination_ip": int(_has_reason(reasons, "new destination ip")),
                        "has_bytes_spike": int(_has_reason(reasons, "bytes sent spike")),
                        "has_burst_activity": int(_has_reason(reasons, "burst activity")),
                    }
                ]
            )
        if metadata.get("model_type") in {"embedding_autoencoder", "zeek_embedding_autoencoder"}:
            embedded_features = metadata["embedded_features"]
            small_categorical_features = metadata["small_categorical_features"]
            numeric_features = metadata["numeric_features"]
            dense_features = _to_dense(
                metadata["dense_preprocessor"].transform(row[small_categorical_features + numeric_features])
            )
            model_inputs: dict[str, np.ndarray] = {"dense_features": dense_features}
            normalized_indices: list[np.ndarray] = []
            for feature in embedded_features:
                vocab = metadata["vocabularies"][feature]
                max_index = max(int(metadata["max_index_values"][feature]), 1)
                index = int(vocab.get(_text(row.iloc[0].get(feature)), 0))
                model_inputs[f"{feature}_input"] = np.asarray([index], dtype=np.int32)
                normalized_indices.append(np.asarray([[index / max_index]], dtype=np.float32))

            target = np.concatenate([*normalized_indices, dense_features], axis=1)
            reconstructed = model.predict(model_inputs, verbose=0)
            reconstruction_error = float(((target - reconstructed) ** 2).mean())
        else:
            feature_columns = metadata["categorical_features"] + metadata["numeric_features"]
            encoded = metadata["preprocessor"].transform(row[feature_columns])
            encoded = _to_dense(encoded)
            reconstructed = model.predict(encoded, verbose=0)
            reconstruction_error = float(((encoded - reconstructed) ** 2).mean())

        threshold = float(metadata.get("reconstruction_threshold", 0.0))
        quarantine_threshold = float(metadata.get("quarantine_threshold", threshold * 2.0))
        if threshold <= 0 or reconstruction_error <= threshold:
            return ACTION_ALLOW, 0.0

        ratio = reconstruction_error / threshold
        if reconstruction_error >= quarantine_threshold:
            confidence = min(0.99, 0.75 + min(ratio - 2.0, 2.0) * 0.1)
            return ACTION_QUARANTINE, confidence

        confidence = min(0.95, 0.65 + min(ratio - 1.0, 1.0) * 0.2)
        return ACTION_BLOCK, confidence
    except Exception:
        return None


def recommend_firewall_action(alert: dict[str, Any]) -> FirewallRecommendation:
    """Recommend a firewall response for one scored alert.

    This combines deterministic safety policy with an optional autoencoder
    anomaly model trained on normal traffic.
    """
    severity = _text(alert.get("severity"))
    reasons = _text(alert.get("reasons"))
    protocol = _text(alert.get("protocol")).upper()
    action = _text(alert.get("action"))
    source_ip = _text(alert.get("source_ip"))
    destination_ip = _text(alert.get("destination_ip"))
    bytes_sent = _score(alert.get("bytes_sent"))
    anomaly_score = _score(alert.get("score"))
    port = _infer_port(protocol, action)
    predicted = _nn_action(alert)
    nn_action, nn_confidence = predicted if predicted else ("", 0.0)
    timestamp = _text(alert.get("timestamp"))
    hour_match = re.search(r"T(\d{2}):", timestamp)
    event_hour = int(hour_match.group(1)) if hour_match else -1
    is_business_hours = 8 <= event_hour < 17

    if "test_site_access" in action.lower():
        if is_business_hours:
            return FirewallRecommendation(
                ai_action=ACTION_MONITOR,
                target_type="source_ip",
                target_value=source_ip,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="HTTP",
                port=port,
                duration_minutes=15,
                confidence=0.68,
                explanation="Client accessed the protected Test Site during the normal 8 AM to 5 PM access window. Monitor this client.",
            )
        return FirewallRecommendation(
            ai_action=ACTION_BLOCK,
            target_type="source_ip",
            target_value=source_ip,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol="HTTP",
            port=port,
            duration_minutes=10,
            confidence=max(0.95, nn_confidence),
            explanation="Client accessed the protected Test Site outside the normal 8 AM to 5 PM window. Block this client IP from the site port.",
        )

    if (nn_action == ACTION_QUARANTINE and nn_confidence >= 0.7) or (severity == "Critical" and anomaly_score >= 4.0):
        if _has_reason(reasons, "burst activity") and _has_reason(reasons, "bytes sent spike"):
            return FirewallRecommendation(
                ai_action=ACTION_QUARANTINE,
                target_type="source_ip",
                target_value=source_ip,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                port=port,
                duration_minutes=60,
                confidence=max(0.94, nn_confidence),
                explanation=(
                    "Critical repeated activity with abnormal data transfer. "
                    "Temporarily quarantine the source host."
                ),
            )
        return FirewallRecommendation(
            ai_action=ACTION_BLOCK,
            target_type="destination_ip",
            target_value=destination_ip,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            duration_minutes=45,
            confidence=max(0.9, nn_confidence),
            explanation="Critical anomaly. Block the suspicious destination while the alert is reviewed.",
        )

    if nn_action == ACTION_BLOCK and nn_confidence >= 0.7 and severity in {"High", "Critical", "Medium"}:
        return FirewallRecommendation(
            ai_action=ACTION_BLOCK,
            target_type="destination_ip",
            target_value=destination_ip,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            duration_minutes=30,
            confidence=nn_confidence,
            explanation="Autoencoder anomaly score recommends blocking this destination.",
        )

    if nn_action == ACTION_QUARANTINE and nn_confidence >= 0.7:
        return FirewallRecommendation(
            ai_action=ACTION_QUARANTINE,
            target_type="source_ip",
            target_value=source_ip,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            duration_minutes=60,
            confidence=nn_confidence,
            explanation="Autoencoder reconstruction error is far above the learned normal-traffic threshold.",
        )

    if nn_action == ACTION_BLOCK and nn_confidence >= 0.7:
        return FirewallRecommendation(
            ai_action=ACTION_BLOCK,
            target_type="destination_ip",
            target_value=destination_ip,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            duration_minutes=30,
            confidence=nn_confidence,
            explanation="Autoencoder reconstruction error exceeds the learned normal-traffic threshold.",
        )

    if severity == "High":
        if "SSH" in protocol or "TELNET" in protocol or port in {22, 23}:
            return FirewallRecommendation(
                ai_action=ACTION_BLOCK,
                target_type="service",
                target_value=f"{destination_ip}:{port or protocol}",
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                port=port,
                duration_minutes=30,
                confidence=0.84,
                explanation="High-risk remote access behavior. Block this service to the destination.",
            )
        if _has_reason(reasons, "bytes sent spike") or bytes_sent >= 16000:
            return FirewallRecommendation(
                ai_action=ACTION_BLOCK,
                target_type="destination_ip",
                target_value=destination_ip,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                port=port,
                duration_minutes=30,
                confidence=0.82,
                explanation="High upload anomaly suggests possible data exfiltration.",
            )

    if severity == "Medium":
        return FirewallRecommendation(
            ai_action=ACTION_MONITOR,
            target_type="user_id",
            target_value=_text(alert.get("user_id")),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            duration_minutes=15,
            confidence=0.66,
            explanation="Suspicious behavior is present, but monitoring is safer than blocking.",
        )

    return FirewallRecommendation(
        ai_action=ACTION_ALLOW,
        target_type="none",
        target_value="",
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        port=port,
        duration_minutes=0,
        confidence=0.4,
        explanation="No firewall action is required for this event.",
    )
