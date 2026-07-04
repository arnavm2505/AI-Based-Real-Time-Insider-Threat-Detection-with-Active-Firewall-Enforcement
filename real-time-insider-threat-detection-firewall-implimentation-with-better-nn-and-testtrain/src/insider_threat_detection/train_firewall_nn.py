from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler

try:
    import tensorflow as tf
except ImportError as error:  # pragma: no cover - friendly CLI failure
    raise SystemExit("Install TensorFlow first: python -m pip install tensorflow") from error

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from insider_threat_detection.pipeline import analyze_events


EMBEDDED_FEATURES = ["user_id", "source_ip", "destination_ip"]
SMALL_CATEGORICAL_FEATURES = ["protocol", "action", "severity"]
NUMERIC_FEATURES = [
    "hour",
    "bytes_sent",
    "bytes_received",
    "score",
    "has_unusual_hour",
    "has_new_source_ip",
    "has_new_destination_ip",
    "has_bytes_spike",
    "has_burst_activity",
]
ZEEK_REQUIRED_COLUMNS = {"src_ip", "dst_ip", "src_port", "dst_port", "proto", "label", "type"}
ZEEK_EMBEDDED_FEATURES = ["src_ip", "dst_ip", "proto", "service", "conn_state", "http_method", "ssl_version", "ssl_cipher"]
ZEEK_SMALL_CATEGORICAL_FEATURES = [
    "http_version",
    "http_orig_mime_types",
    "http_resp_mime_types",
    "weird_notice",
]
ZEEK_NUMERIC_FEATURES = [
    "src_port",
    "dst_port",
    "duration",
    "src_bytes",
    "dst_bytes",
    "missed_bytes",
    "src_pkts",
    "dst_pkts",
    "src_ip_bytes",
    "dst_ip_bytes",
    "dns_qclass",
    "dns_qtype",
    "dns_rcode",
    "http_trans_depth",
    "http_request_body_len",
    "http_response_body_len",
    "http_status_code",
    "total_bytes",
    "total_pkts",
    "byte_ratio",
    "pkt_ratio",
    "bytes_per_packet",
    "dns_query_length",
    "http_uri_length",
    "user_agent_length",
    "dns_AA",
    "dns_RD",
    "dns_RA",
    "dns_rejected",
    "ssl_resumed",
    "ssl_established",
    "has_dns_query",
    "has_ssl_subject",
    "has_ssl_issuer",
    "has_http_uri",
    "has_user_agent",
    "has_weird_name",
    "has_weird_addl",
    "is_common_dst_port",
    "is_privileged_dst_port",
]


def _flag_reason(reasons: str, phrase: str) -> int:
    return int(phrase in reasons.lower())


def _one_hot_encoder() -> OneHotEncoder:
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=False)


def _build_vocab(values: pd.Series) -> dict[str, int]:
    unique_values = sorted(str(value) for value in values.dropna().unique())
    return {"<UNK>": 0, **{value: index + 1 for index, value in enumerate(unique_values)}}


def _embedding_dim(vocab_size: int) -> int:
    return max(2, min(16, int(np.ceil(np.sqrt(vocab_size))) + 1))


def _feature_indices(
    frame: pd.DataFrame,
    vocabularies: dict[str, dict[str, int]],
    embedded_features: list[str],
) -> dict[str, np.ndarray]:
    inputs: dict[str, np.ndarray] = {}
    for feature in embedded_features:
        vocab = vocabularies[feature]
        inputs[f"{feature}_input"] = (
            frame[feature].astype(str).map(lambda value: vocab.get(value, 0)).to_numpy(dtype=np.int32)
        )
    return inputs


def _normalized_indices(
    frame: pd.DataFrame,
    vocabularies: dict[str, dict[str, int]],
    max_index_values: dict[str, int],
    embedded_features: list[str],
) -> np.ndarray:
    columns = []
    for feature in embedded_features:
        vocab = vocabularies[feature]
        max_index = max(max_index_values[feature], 1)
        values = frame[feature].astype(str).map(lambda value: vocab.get(value, 0)).to_numpy(dtype=np.float32)
        columns.append((values / max_index).reshape(-1, 1))
    return np.concatenate(columns, axis=1).astype(np.float32)


def _to_dense(matrix: object) -> np.ndarray:
    if hasattr(matrix, "toarray"):
        matrix = matrix.toarray()
    return np.asarray(matrix, dtype=np.float32)


def _build_model(
    vocabularies: dict[str, dict[str, int]],
    embedded_features: list[str],
    dense_dim: int,
    target_dim: int,
) -> tf.keras.Model:
    model_inputs: list[tf.keras.layers.Input] = []
    encoded_parts: list[tf.Tensor] = []

    for feature in embedded_features:
        vocab_size = len(vocabularies[feature])
        embedding_size = _embedding_dim(vocab_size)
        feature_input = tf.keras.layers.Input(shape=(), dtype="int32", name=f"{feature}_input")
        embedding = tf.keras.layers.Embedding(
            input_dim=vocab_size,
            output_dim=embedding_size,
            name=f"{feature}_embedding",
        )(feature_input)
        model_inputs.append(feature_input)
        encoded_parts.append(tf.keras.layers.Flatten()(embedding))

    dense_input = tf.keras.layers.Input(shape=(dense_dim,), name="dense_features")
    model_inputs.append(dense_input)
    encoded_parts.append(dense_input)

    merged = tf.keras.layers.Concatenate(name="embedded_event_features")(encoded_parts)
    hidden = tf.keras.layers.Dense(96, activation="relu")(merged)
    hidden = tf.keras.layers.Dropout(0.2)(hidden)
    hidden = tf.keras.layers.Dense(48, activation="relu")(hidden)
    bottleneck = tf.keras.layers.Dense(16, activation="relu", name="behavior_bottleneck")(hidden)
    hidden = tf.keras.layers.Dense(48, activation="relu")(bottleneck)
    hidden = tf.keras.layers.Dense(96, activation="relu")(hidden)
    output = tf.keras.layers.Dense(target_dim, activation="linear", name="reconstructed_event")(hidden)

    model = tf.keras.Model(inputs=model_inputs, outputs=output, name="embedding_autoencoder")
    model.compile(optimizer="adam", loss="mse")
    return model


def _clean_text(value: object) -> str:
    text = str(value if value is not None else "").strip()
    return "" if text in {"", "-", "nan", "None"} else text


def _binary_flag(value: object) -> int:
    text = _clean_text(value).lower()
    return int(text in {"1", "t", "true", "yes"})


def _numeric_series(frame: pd.DataFrame, column: str) -> pd.Series:
    return pd.to_numeric(frame.get(column, 0), errors="coerce").fillna(0.0)


def _text_length(frame: pd.DataFrame, column: str) -> pd.Series:
    return frame.get(column, "").map(_clean_text).str.len().fillna(0).astype(float)


def _has_text(frame: pd.DataFrame, column: str) -> pd.Series:
    return frame.get(column, "").map(lambda value: int(bool(_clean_text(value)))).astype(float)


def _build_zeek_training_frame(csv_path: Path) -> pd.DataFrame:
    frame = pd.read_csv(csv_path, low_memory=False).replace("-", "")

    for column in ZEEK_EMBEDDED_FEATURES + ZEEK_SMALL_CATEGORICAL_FEATURES:
        frame[column] = frame.get(column, "").map(_clean_text)

    for column in [
        "src_port",
        "dst_port",
        "duration",
        "src_bytes",
        "dst_bytes",
        "missed_bytes",
        "src_pkts",
        "dst_pkts",
        "src_ip_bytes",
        "dst_ip_bytes",
        "dns_qclass",
        "dns_qtype",
        "dns_rcode",
        "http_trans_depth",
        "http_request_body_len",
        "http_response_body_len",
        "http_status_code",
    ]:
        frame[column] = _numeric_series(frame, column)

    frame["total_bytes"] = frame["src_bytes"] + frame["dst_bytes"]
    frame["total_pkts"] = frame["src_pkts"] + frame["dst_pkts"]
    frame["byte_ratio"] = frame["src_bytes"] / (frame["dst_bytes"] + 1.0)
    frame["pkt_ratio"] = frame["src_pkts"] / (frame["dst_pkts"] + 1.0)
    frame["bytes_per_packet"] = frame["total_bytes"] / (frame["total_pkts"] + 1.0)
    frame["dns_query_length"] = _text_length(frame, "dns_query")
    frame["http_uri_length"] = _text_length(frame, "http_uri")
    frame["user_agent_length"] = _text_length(frame, "http_user_agent")
    frame["has_dns_query"] = _has_text(frame, "dns_query")
    frame["has_ssl_subject"] = _has_text(frame, "ssl_subject")
    frame["has_ssl_issuer"] = _has_text(frame, "ssl_issuer")
    frame["has_http_uri"] = _has_text(frame, "http_uri")
    frame["has_user_agent"] = _has_text(frame, "http_user_agent")
    frame["has_weird_name"] = _has_text(frame, "weird_name")
    frame["has_weird_addl"] = _has_text(frame, "weird_addl")
    frame["dns_AA"] = frame.get("dns_AA", "").map(_binary_flag).astype(float)
    frame["dns_RD"] = frame.get("dns_RD", "").map(_binary_flag).astype(float)
    frame["dns_RA"] = frame.get("dns_RA", "").map(_binary_flag).astype(float)
    frame["dns_rejected"] = frame.get("dns_rejected", "").map(_binary_flag).astype(float)
    frame["ssl_resumed"] = frame.get("ssl_resumed", "").map(_binary_flag).astype(float)
    frame["ssl_established"] = frame.get("ssl_established", "").map(_binary_flag).astype(float)
    frame["is_common_dst_port"] = frame["dst_port"].isin([22, 53, 80, 443, 8080]).astype(float)
    frame["is_privileged_dst_port"] = (frame["dst_port"] < 1024).astype(float)
    frame["is_normal"] = (frame["label"].astype(str).str.lower().isin(["0", "normal"])) | (
        frame["type"].astype(str).str.lower() == "normal"
    )
    return frame


def build_training_frame(csv_path: Path) -> pd.DataFrame:
    header = pd.read_csv(csv_path, nrows=0)
    if ZEEK_REQUIRED_COLUMNS.issubset(set(header.columns)):
        return _build_zeek_training_frame(csv_path)

    scored_events, _ = analyze_events(csv_path)
    if not scored_events:
        raise ValueError(f"No scored events found in {csv_path}")

    frame = pd.DataFrame(scored_events)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    frame["hour"] = frame["timestamp"].dt.hour
    frame["has_unusual_hour"] = frame["reasons"].apply(lambda value: _flag_reason(value, "unusual access hour"))
    frame["has_new_source_ip"] = frame["reasons"].apply(lambda value: _flag_reason(value, "new source ip"))
    frame["has_new_destination_ip"] = frame["reasons"].apply(lambda value: _flag_reason(value, "new destination ip"))
    frame["has_bytes_spike"] = frame["reasons"].apply(lambda value: _flag_reason(value, "bytes sent spike"))
    frame["has_burst_activity"] = frame["reasons"].apply(lambda value: _flag_reason(value, "burst activity"))
    return frame


def train(csv_path: Path, model_path: Path, preprocessor_path: Path) -> None:
    frame = build_training_frame(csv_path)
    if ZEEK_REQUIRED_COLUMNS.issubset(set(frame.columns)):
        embedded_features = ZEEK_EMBEDDED_FEATURES
        small_categorical_features = ZEEK_SMALL_CATEGORICAL_FEATURES
        numeric_features = ZEEK_NUMERIC_FEATURES
        model_type = "zeek_embedding_autoencoder"
        normal_frame = frame[frame["is_normal"]].copy()
    else:
        embedded_features = EMBEDDED_FEATURES
        small_categorical_features = SMALL_CATEGORICAL_FEATURES
        numeric_features = NUMERIC_FEATURES
        model_type = "embedding_autoencoder"
        normal_frame = frame[
            (frame["severity"].isin(["Normal", "Low"]))
            & (frame["score"].astype(float) < 2.5)
        ].copy()
    if normal_frame.empty:
        raise ValueError("No normal/low-risk events found. Autoencoder training needs clean baseline traffic.")

    feature_columns = embedded_features + small_categorical_features + numeric_features
    x_train, x_test = train_test_split(
        normal_frame[feature_columns],
        test_size=0.2,
        random_state=42,
    )

    vocabularies = {feature: _build_vocab(x_train[feature]) for feature in embedded_features}
    max_index_values = {feature: max(vocabularies[feature].values()) for feature in embedded_features}
    dense_preprocessor = ColumnTransformer(
        transformers=[
            ("categorical", _one_hot_encoder(), small_categorical_features),
            ("numeric", StandardScaler(), numeric_features),
        ]
    )

    x_train_dense = _to_dense(dense_preprocessor.fit_transform(x_train))
    x_test_dense = _to_dense(dense_preprocessor.transform(x_test))
    train_inputs = _feature_indices(x_train, vocabularies, embedded_features)
    test_inputs = _feature_indices(x_test, vocabularies, embedded_features)
    train_inputs["dense_features"] = x_train_dense
    test_inputs["dense_features"] = x_test_dense

    y_train = np.concatenate(
        [_normalized_indices(x_train, vocabularies, max_index_values, embedded_features), x_train_dense],
        axis=1,
    )
    y_test = np.concatenate(
        [_normalized_indices(x_test, vocabularies, max_index_values, embedded_features), x_test_dense],
        axis=1,
    )

    model = _build_model(vocabularies, embedded_features, dense_dim=x_train_dense.shape[1], target_dim=y_train.shape[1])
    model.fit(
        train_inputs,
        y_train,
        validation_data=(test_inputs, y_test),
        epochs=50,
        batch_size=32,
        verbose=1,
    )

    reconstructed = model.predict(train_inputs, verbose=0)
    reconstruction_errors = ((y_train - reconstructed) ** 2).mean(axis=1)
    threshold = float(pd.Series(reconstruction_errors).quantile(0.95))
    quarantine_threshold = float(threshold * 2.0)
    print(f"Trained embedding autoencoder on {len(y_train)} normal events")
    print(f"Dense feature dimensions: {x_train_dense.shape[1]}")
    print(f"Reconstruction target dimensions: {y_train.shape[1]}")
    print(f"95th percentile reconstruction threshold: {threshold:.6f}")

    model_path.parent.mkdir(parents=True, exist_ok=True)
    preprocessor_path.parent.mkdir(parents=True, exist_ok=True)
    model.save(model_path)
    with preprocessor_path.open("wb") as file:
        pickle.dump(
            {
                "dense_preprocessor": dense_preprocessor,
                "embedded_features": embedded_features,
                "small_categorical_features": small_categorical_features,
                "numeric_features": numeric_features,
                "vocabularies": vocabularies,
                "max_index_values": max_index_values,
                "model_type": model_type,
                "reconstruction_threshold": threshold,
                "quarantine_threshold": quarantine_threshold,
            },
            file,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the autoencoder firewall anomaly model.")
    parser.add_argument("--csv-path", type=Path, default=Path("data") / "network_events.csv")
    parser.add_argument("--model-path", type=Path, default=Path("models") / "firewall_nn.keras")
    parser.add_argument("--preprocessor-path", type=Path, default=Path("models") / "firewall_preprocessor.pkl")
    args = parser.parse_args()

    train(args.csv_path, args.model_path, args.preprocessor_path)


if __name__ == "__main__":
    main()
