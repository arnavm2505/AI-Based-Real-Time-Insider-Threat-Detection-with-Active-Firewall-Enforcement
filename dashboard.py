import sys
from pathlib import Path

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from insider_threat_detection.pipeline import analyze_events
from insider_threat_detection.simulator import (
    append_live_events_csv,
    append_sample_events_csv,
    generate_sample_events_csv,
)

DATA_PATH = PROJECT_ROOT / "data" / "network_events.csv"


@st.cache_data
def load_dashboard_data(csv_path: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    scored_events, alerts = analyze_events(Path(csv_path))
    events_df = pd.DataFrame(scored_events)
    alerts_df = pd.DataFrame(alerts)

    if not events_df.empty:
        events_df["timestamp"] = pd.to_datetime(events_df["timestamp"])
        events_df["hour"] = events_df["timestamp"].dt.hour

    if not alerts_df.empty:
        alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"])
        alerts_df["score"] = alerts_df["score"].astype(float)

    return events_df, alerts_df


def severity_badge_html(severity: str) -> str:
    colors = {
        "Critical": ("#7f1d1d", "#fecaca"),
        "High": ("#9a3412", "#fed7aa"),
        "Medium": ("#854d0e", "#fde68a"),
        "Low": ("#1d4ed8", "#bfdbfe"),
        "Normal": ("#166534", "#bbf7d0"),
    }
    text_color, bg_color = colors.get(severity, ("#374151", "#e5e7eb"))
    return (
        f"<span style='display:inline-block;padding:0.2rem 0.55rem;border-radius:999px;"
        f"font-weight:600;color:{text_color};background:{bg_color};'>{severity}</span>"
    )


def ensure_sample_data() -> None:
    if not DATA_PATH.exists():
        DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        generate_sample_events_csv(DATA_PATH, user_count=6, events_per_user=80)


def build_sidebar(events_df: pd.DataFrame) -> dict[str, object]:
    st.sidebar.header("Controls")

    selected_user = "All users"
    if not events_df.empty:
        users = sorted(events_df["user_id"].unique().tolist())
        selected_user = st.sidebar.selectbox("User", ["All users", *users])

    top_n = st.sidebar.slider("Recent alerts to show", min_value=5, max_value=50, value=10, step=5)
    auto_refresh = st.sidebar.toggle("Auto-refresh dashboard", value=False)
    refresh_seconds = st.sidebar.slider("Refresh interval (seconds)", min_value=2, max_value=30, value=5)
    live_simulation = st.sidebar.toggle("Live simulation mode", value=False)
    events_per_refresh = st.sidebar.slider("Events per refresh", min_value=2, max_value=20, value=6, step=2)

    if st.sidebar.button("Append live event batch"):
        append_live_events_csv(DATA_PATH, user_count=6, events_to_add=int(events_per_refresh))
        st.cache_data.clear()
        st.rerun()

    if st.sidebar.button("Append sample data batch"):
        append_sample_events_csv(DATA_PATH, user_count=6, events_per_user=80)
        st.cache_data.clear()
        st.rerun()

    return {
        "selected_user": selected_user,
        "top_n": top_n,
        "auto_refresh": auto_refresh,
        "refresh_seconds": refresh_seconds,
        "live_simulation": live_simulation,
        "events_per_refresh": events_per_refresh,
    }


def maybe_stream_new_events(auto_refresh: bool, live_simulation: bool, events_per_refresh: int) -> None:
    if not auto_refresh:
        return

    interval_ms = int(st.session_state.get("refresh_seconds", 5)) * 1000
    refresh_count = st_autorefresh(interval=interval_ms, key="dashboard_autorefresh")

    if live_simulation and refresh_count > 0:
        last_tick = st.session_state.get("last_live_tick")
        if last_tick != refresh_count:
            append_live_events_csv(DATA_PATH, user_count=6, events_to_add=events_per_refresh)
            st.session_state["last_live_tick"] = refresh_count
            st.cache_data.clear()


def main() -> None:
    st.set_page_config(
        page_title="Insider Threat Detection Dashboard",
        layout="wide",
    )

    ensure_sample_data()
    events_df, alerts_df = load_dashboard_data(str(DATA_PATH))
    controls = build_sidebar(events_df)
    st.session_state["refresh_seconds"] = controls["refresh_seconds"]
    maybe_stream_new_events(
        auto_refresh=bool(controls["auto_refresh"]),
        live_simulation=bool(controls["live_simulation"]),
        events_per_refresh=int(controls["events_per_refresh"]),
    )
    events_df, alerts_df = load_dashboard_data(str(DATA_PATH))
    selected_user = str(controls["selected_user"])
    top_n = int(controls["top_n"])

    st.title("Real-Time Insider Threat Detection")
    st.caption("Network behavior profiling dashboard for suspicious insider activity")
    if bool(controls["auto_refresh"]):
        st.info(
            f"Auto-refresh is running every {int(controls['refresh_seconds'])} seconds."
            + (
                f" Live simulation is appending {int(controls['events_per_refresh'])} events each cycle."
                if bool(controls["live_simulation"])
                else ""
            )
        )

    if events_df.empty:
        st.warning("No event data is available yet.")
        return

    filtered_events = events_df.copy()
    filtered_alerts = alerts_df.copy()
    if selected_user != "All users":
        filtered_events = filtered_events[filtered_events["user_id"] == selected_user]
        filtered_alerts = filtered_alerts[filtered_alerts["user_id"] == selected_user]

    total_events = int(len(filtered_events))
    total_alerts = int(len(filtered_alerts))
    alert_rate = (total_alerts / total_events * 100) if total_events else 0.0
    avg_score = float(filtered_events["score"].mean()) if total_events else 0.0
    critical_count = int((filtered_alerts["severity"] == "Critical").sum()) if total_alerts else 0

    metric_columns = st.columns(4)
    metric_columns[0].metric("Events processed", total_events)
    metric_columns[1].metric("Alerts raised", total_alerts)
    metric_columns[2].metric("Alert rate", f"{alert_rate:.1f}%")
    metric_columns[3].metric(
        "Average score / Critical",
        f"{avg_score:.2f}",
        delta=f"{critical_count} critical",
    )

    timeline_col, user_col = st.columns(2)

    with timeline_col:
        st.subheader("Alert timeline")
        if filtered_alerts.empty:
            st.info("No alerts for the current filter.")
        else:
            alert_timeline = (
                filtered_alerts.set_index("timestamp")
                .resample("1h")
                .size()
                .rename("alerts")
            )
            st.line_chart(alert_timeline)

    with user_col:
        st.subheader("Alert counts by user")
        alert_counts = (
            filtered_events[filtered_events["alert"]]
            .groupby("user_id")
            .size()
            .sort_values(ascending=False)
        )
        if alert_counts.empty:
            st.info("No alert counts to display.")
        else:
            st.bar_chart(alert_counts)

    st.subheader("Severity overview")
    if filtered_alerts.empty:
        st.info("No alert severity data to display.")
    else:
        severity_counts = (
            filtered_alerts["severity"]
            .value_counts()
            .reindex(["Critical", "High", "Medium", "Low"], fill_value=0)
        )
        severity_columns = st.columns(4)
        for column, severity in zip(severity_columns, severity_counts.index):
            column.markdown(severity_badge_html(severity), unsafe_allow_html=True)
            column.metric(f"{severity} alerts", int(severity_counts[severity]))

    volume_col, score_col = st.columns(2)

    with volume_col:
        st.subheader("Traffic volume over time")
        volume_timeline = (
            filtered_events.set_index("timestamp")[["bytes_sent", "bytes_received"]]
            .resample("1h")
            .sum()
        )
        st.area_chart(volume_timeline)

    with score_col:
        st.subheader("Average score by hour")
        score_by_hour = filtered_events.groupby("hour")["score"].mean().sort_index()
        st.bar_chart(score_by_hour)

    st.subheader("Most common alert reasons")
    if filtered_alerts.empty:
        st.info("No alert reasons to summarize.")
    else:
        reason_counts = (
            filtered_alerts["reasons"]
            .str.split(", ")
            .explode()
            .value_counts()
        )
        st.bar_chart(reason_counts)

    st.subheader("Recent alerts")
    if filtered_alerts.empty:
        st.info("No recent alerts to show.")
    else:
        recent_alerts = filtered_alerts.sort_values("timestamp", ascending=False).head(top_n)
        st.markdown(
            "".join(
                f"{severity_badge_html(severity)} "
                for severity in recent_alerts["severity"].tolist()[: min(4, len(recent_alerts))]
            ),
            unsafe_allow_html=True,
        )
        st.dataframe(recent_alerts, use_container_width=True, hide_index=True)

        st.download_button(
            label="Download alerts CSV",
            data=filtered_alerts.sort_values("timestamp", ascending=False).to_csv(index=False).encode("utf-8"),
            file_name="insider_threat_alerts.csv",
            mime="text/csv",
        )

    st.subheader("Scored event stream")
    display_columns = [
        "timestamp",
        "user_id",
        "source_ip",
        "destination_ip",
        "protocol",
        "action",
        "bytes_sent",
        "bytes_received",
        "score",
        "alert",
        "severity",
        "reasons",
    ]
    st.dataframe(
        filtered_events.sort_values("timestamp", ascending=False)[display_columns],
        use_container_width=True,
        hide_index=True,
    )
    st.download_button(
        label="Download scored events CSV",
        data=filtered_events.sort_values("timestamp", ascending=False)[display_columns]
        .to_csv(index=False)
        .encode("utf-8"),
        file_name="insider_threat_scored_events.csv",
        mime="text/csv",
    )


if __name__ == "__main__":
    main()
