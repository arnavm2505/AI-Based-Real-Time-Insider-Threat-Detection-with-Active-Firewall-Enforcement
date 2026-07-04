import React from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Play,
  RadioTower,
  RefreshCw,
  Shield,
  ShieldAlert,
  Square,
  XCircle,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8001";
const REFRESH_INTERVAL_MS = 60000;

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }
  return response.json();
}

function severityClass(value) {
  return `severity ${String(value || "normal").toLowerCase()}`;
}

function actionClass(value) {
  return `action ${String(value || "allow").toLowerCase()}`;
}

function MetricCard({ icon: Icon, label, value, detail }) {
  return (
    <section className="metric-card">
      <div className="metric-icon">
        <Icon size={20} />
      </div>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
        <span>{detail}</span>
      </div>
    </section>
  );
}

function CollectorControls({ collector, onRefresh }) {
  const [busy, setBusy] = React.useState(false);

  async function runAction(path, body) {
    setBusy(true);
    try {
      await api(path, body ? { method: "POST", body: JSON.stringify(body) } : { method: "POST" });
      await onRefresh();
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel controls-panel">
      <div className="panel-title">
        <RadioTower size={20} />
        <div>
          <h2>Collector</h2>
          <p>{collector.running ? "Live simulation is streaming event batches." : "Collector is paused."}</p>
        </div>
      </div>
      <div className="control-row">
        <button
          className="primary"
          disabled={busy || collector.running}
          onClick={() => runAction("/api/collector/start", { interval_seconds: 5, events_per_batch: 6 })}
        >
          <Play size={16} /> Start
        </button>
        <button
          className="secondary"
          disabled={busy || !collector.running}
          onClick={() => runAction("/api/collector/stop")}
        >
          <Square size={16} /> Stop
        </button>
        <button
          className="secondary"
          disabled={busy}
          onClick={() => runAction("/api/simulate/live", { interval_seconds: 5, events_per_batch: 8 })}
        >
          <RefreshCw size={16} /> Append Batch
        </button>
      </div>
      <div className="collector-state">
        <span className={collector.running ? "dot online" : "dot"} />
        <span>{collector.running ? "Running" : "Stopped"}</span>
        <span>{collector.interval_seconds || 5}s interval</span>
        <span>{collector.events_per_batch || 6} events/batch</span>
        <span>Dashboard refreshes every 1 minute</span>
      </div>
    </section>
  );
}

function FirewallAdvisor({ recommendations, rules, onAction }) {
  const pending = recommendations.filter((item) => item.status === "pending").slice(0, 8);
  const activeRules = rules.filter((rule) => rule.status === "active").slice(0, 6);

  return (
    <section className="panel firewall-panel">
      <div className="panel-title">
        <ShieldAlert size={20} />
        <div>
          <h2>AI Firewall Advisor</h2>
          <p>Autoencoder anomaly layer with real/app-enforced firewall actions.</p>
        </div>
      </div>

      <div className="advisor-grid">
        <div>
          <h3>Pending Decisions</h3>
          <div className="decision-list">
            {pending.length === 0 && <p className="empty">No pending recommendations.</p>}
            {pending.map((item) => (
              <article className="decision" key={item.id}>
                <div>
                  <span className={severityClass(item.severity)}>{item.severity}</span>
                  <span className={actionClass(item.ai_action)}>{item.ai_action}</span>
                </div>
                <strong>{item.source_ip} {"->"} {item.destination_ip}</strong>
                <p>{item.explanation}</p>
                <div className="decision-meta">
                  <span>{item.protocol || "ANY"}</span>
                  <span>{Math.round(Number(item.confidence) * 100)}% confidence</span>
                  <span>{item.duration_minutes} min</span>
                </div>
                <div className="decision-actions">
                  <button className="approve" onClick={() => onAction("/api/firewall/approve", { recommendation_id: item.id })}>
                    <CheckCircle2 size={15} /> Approve
                  </button>
                  <button className="reject" onClick={() => onAction("/api/firewall/reject", { recommendation_id: item.id })}>
                    <XCircle size={15} /> Reject
                  </button>
                </div>
              </article>
            ))}
          </div>
        </div>

        <div>
          <h3>Active Firewall Rules</h3>
          <div className="rule-list">
            {activeRules.length === 0 && <p className="empty">No active firewall rules.</p>}
            {activeRules.map((rule) => (
              <article className="rule" key={rule.id}>
                <div>
                  <Ban size={16} />
                  <strong>{rule.action}</strong>
                  <span>{rule.mode}</span>
                </div>
                <p>{rule.target_type}: {rule.target_value}</p>
                <small>{rule.reason}</small>
                <button className="secondary compact" onClick={() => onAction("/api/firewall/unblock", { rule_id: rule.id })}>
                  Unblock
                </button>
              </article>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function EventsTable({ events }) {
  return (
    <section className="panel">
      <div className="panel-title">
        <Activity size={20} />
        <div>
          <h2>Scored Event Stream</h2>
          <p>Latest analyzed network behavior records.</p>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>User</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Score</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {events.slice(0, 14).map((event, index) => (
              <tr key={`${event.timestamp}-${event.user_id}-${index}`}>
                <td>{event.timestamp?.replace("T", " ").slice(0, 16)}</td>
                <td>{event.user_id}</td>
                <td>{event.source_ip}</td>
                <td>{event.destination_ip}</td>
                <td>{event.protocol}</td>
                <td>{Number(event.score).toFixed(2)}</td>
                <td><span className={severityClass(event.severity)}>{event.severity}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function App() {
  const [summary, setSummary] = React.useState(null);
  const [events, setEvents] = React.useState([]);
  const [recommendations, setRecommendations] = React.useState([]);
  const [rules, setRules] = React.useState([]);
  const [collector, setCollector] = React.useState({});
  const [error, setError] = React.useState("");

  const refresh = React.useCallback(async () => {
    try {
      const [summaryData, eventData, recommendationData, ruleData, collectorData] = await Promise.all([
        api("/api/summary"),
        api("/api/events"),
        api("/api/firewall/recommendations"),
        api("/api/firewall/rules"),
        api("/api/collector/status"),
      ]);
      setSummary(summaryData);
      setEvents((eventData.events || []).slice().reverse());
      setRecommendations((recommendationData.recommendations || []).slice().reverse());
      setRules((ruleData.rules || []).slice().reverse());
      setCollector(collectorData);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }, []);

  React.useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, REFRESH_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  async function runFirewallAction(path, payload) {
    try {
      await api(path, { method: "POST", body: JSON.stringify(payload) });
      await refresh();
      setError("");
    } catch (err) {
      setError(`Firewall action failed: ${err.message}`);
    }
  }

  const severityData = summary
    ? Object.entries(summary.severity_counts).map(([severity, count]) => ({ severity, count }))
    : [];

  return (
    <main>
      <header className="app-header">
        <div className="brand-mark">
          <Shield size={28} />
        </div>
        <div>
          <p className="eyebrow">AI Insider Threat Defense</p>
          <h1>Security Command Center</h1>
          <p className="refresh-note">Auto-refreshes every 1 minute.</p>
        </div>
        <button className="secondary refresh-button" onClick={refresh}>
          <RefreshCw size={16} /> Refresh
        </button>
      </header>

      {error && <div className="error"><AlertTriangle size={16} /> {error}</div>}

      <section className="metrics-grid">
        <MetricCard icon={Activity} label="Events Processed" value={summary?.total_events ?? "--"} detail="scored rows" />
        <MetricCard icon={AlertTriangle} label="Alerts Raised" value={summary?.total_alerts ?? "--"} detail={`${summary?.alert_rate ?? 0}% alert rate`} />
        <MetricCard icon={ShieldAlert} label="Critical Alerts" value={summary?.critical_count ?? "--"} detail="auto-block candidates" />
        <MetricCard icon={Shield} label="Average Score" value={summary?.average_score ?? "--"} detail="behavior risk" />
      </section>

      <div className="main-grid">
        <CollectorControls collector={collector} onRefresh={refresh} />
        <section className="panel chart-panel">
          <h2>Alert Severity</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="severity" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" fill="#df5b43" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </section>
      </div>

      <div className="chart-grid">
        <section className="panel chart-panel">
          <h2>Traffic Volume</h2>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={summary?.traffic_by_hour || []}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="hour" tickFormatter={(value) => String(value).slice(11)} />
              <YAxis />
              <Tooltip />
              <Area type="monotone" dataKey="bytes_sent" stackId="1" stroke="#2f80ed" fill="#b9d8ff" />
              <Area type="monotone" dataKey="bytes_received" stackId="1" stroke="#1f9d73" fill="#bdebd9" />
            </AreaChart>
          </ResponsiveContainer>
        </section>
        <section className="panel chart-panel">
          <h2>Average Score</h2>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={summary?.score_by_hour || []}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="hour" tickFormatter={(value) => String(value).slice(11)} />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="score" stroke="#7a5af8" strokeWidth={3} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </section>
      </div>

      <FirewallAdvisor recommendations={recommendations} rules={rules} onAction={runFirewallAction} />
      <EventsTable events={events} />
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
