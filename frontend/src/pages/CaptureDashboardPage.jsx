import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getCapture, getReportUrl } from "../api/client";
import { PostureGauge } from "../components/PostureGauge";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEVERITY_COLOR = {
  CRITICAL: "#f0454f",
  HIGH: "#f5943a",
  MEDIUM: "#e0c341",
  LOW: "#4f9df0",
  INFO: "#6b7685",
};

function isComplete(c) {
  return c.sessions !== undefined;
}

export function CaptureDashboardPage() {
  const { captureId } = useParams();
  const [capture, setCapture] = useState(null);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!captureId) return;
    const id = captureId;
    let cancelled = false;
    let timer;

    function poll() {
      getCapture(id)
        .then((res) => {
          if (cancelled) return;
          setCapture(res);
          if (res.status === "PENDING" || res.status === "RUNNING") {
            timer = window.setTimeout(poll, 1500);
          }
        })
        .catch((e) => !cancelled && setError(e instanceof Error ? e.message : "failed to load"));
    }
    poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [captureId]);

  if (error) return <div className="p-4 text-sev-critical font-mono text-[12px]">{error}</div>;
  if (!capture) return <div className="p-4 text-text-faint font-mono text-[12px]">loading...</div>;

  if (!isComplete(capture)) {
    return (
      <div className="p-4 max-w-[1400px] w-full mx-auto flex flex-col gap-3">
        <Breadcrumb filename={capture.filename} />
        <div className="border border-border bg-panel p-6 flex items-center gap-3">
          <StatusBadge status={capture.status} />
          <span className="font-mono text-[12px] text-text-dim">
            {capture.status === "FAILED" ? capture.error : "analysis in progress..."}
          </span>
        </div>
      </div>
    );
  }

  const findingCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const session of capture.sessions) {
    for (const f of session.findings) findingCounts[f.severity]++;
  }
  const chartData = SEVERITY_ORDER.map((sev) => ({ severity: sev, count: findingCounts[sev] }));

  return (
    <div className="p-4 max-w-[1400px] w-full mx-auto flex flex-col gap-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <Breadcrumb filename={capture.summary.capture_file} />
        <ReportDownloads captureId={captureId} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="border border-border bg-panel p-4 flex items-center gap-4">
          <PostureGauge score={capture.summary.overall_health_score} riskLevel={capture.summary.risk_level} />
          <div className="flex flex-col gap-1.5">
            <span className="text-[10px] font-mono tracking-widest text-text-faint uppercase">
              overall posture
            </span>
            <SeverityBadge severity={capture.summary.risk_level} />
            <span className="text-[11px] font-mono text-text-dim">
              {capture.summary.total_sessions_analyzed} session
              {capture.summary.total_sessions_analyzed === 1 ? "" : "s"} analyzed
            </span>
          </div>
        </div>

        <div className="lg:col-span-2 border border-border bg-panel p-3">
          <span className="text-[10px] font-mono tracking-widest text-text-faint uppercase">
            findings by severity
          </span>
          <ResponsiveContainer width="100%" height={110}>
            <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="2 4" stroke="#1a2130" vertical={false} />
              <XAxis
                dataKey="severity"
                tick={{ fill: "#8592a6", fontSize: 10, fontFamily: "JetBrains Mono" }}
                axisLine={{ stroke: "#232c3d" }}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "#8592a6", fontSize: 10, fontFamily: "JetBrains Mono" }}
                axisLine={{ stroke: "#232c3d" }}
                tickLine={false}
              />
              <Tooltip
                cursor={{ fill: "#141a29" }}
                contentStyle={{
                  background: "#0f1420",
                  border: "1px solid #232c3d",
                  borderRadius: 0,
                  fontFamily: "JetBrains Mono",
                  fontSize: 11,
                }}
              />
              <Bar dataKey="count">
                {chartData.map((d) => (
                  <Cell key={d.severity} fill={SEVERITY_COLOR[d.severity]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {capture.summary.attack_surface && <AttackSurfacePanel surface={capture.summary.attack_surface} />}

      <div className="border border-border bg-panel">
        <div className="px-3 py-2 border-b border-border-soft">
          <span className="text-[11px] font-mono tracking-widest text-text-dim uppercase">
            Sessions ({capture.sessions.length})
          </span>
        </div>
        <table className="w-full text-[12px] font-mono border-collapse">
          <thead>
            <tr className="text-text-faint text-left border-b border-border-soft uppercase text-[10px] tracking-wider">
              <th className="px-3 py-1.5 font-medium">Session</th>
              <th className="px-3 py-1.5 font-medium">Protocol</th>
              <th className="px-3 py-1.5 font-medium">Client</th>
              <th className="px-3 py-1.5 font-medium">Server</th>
              <th className="px-3 py-1.5 font-medium">STARTTLS</th>
              <th className="px-3 py-1.5 font-medium">TLS</th>
              <th className="px-3 py-1.5 font-medium">Cipher</th>
              <th className="px-3 py-1.5 font-medium">Findings</th>
              <th className="px-3 py-1.5 font-medium">Score</th>
              <th className="px-3 py-1.5 font-medium">Risk</th>
            </tr>
          </thead>
          <tbody>
            {capture.sessions.map((s) => (
              <tr
                key={s.session_id}
                onClick={() => navigate(`/captures/${captureId}/sessions/${s.session_id}`)}
                className="border-b border-border-soft hover:bg-panel-alt cursor-pointer"
              >
                <td className="px-3 py-1.5 text-accent">{s.session_id}</td>
                <td className="px-3 py-1.5 text-text-dim">{s.protocol}</td>
                <td className="px-3 py-1.5 text-text-dim">
                  {s.client.ip}:{s.client.port}
                </td>
                <td className="px-3 py-1.5 text-text-dim">
                  {s.server.ip}:{s.server.port}
                </td>
                <td className="px-3 py-1.5 text-text-dim">{s.starttls_negotiation.status}</td>
                <td className="px-3 py-1.5 text-text-dim">{s.tls_handshake.version_negotiated ?? "—"}</td>
                <td className="px-3 py-1.5 text-text-dim truncate max-w-[220px]">
                  {s.tls_handshake.cipher_suite_selected ?? "—"}
                </td>
                <td className="px-3 py-1.5 text-text-dim">{s.findings.length}</td>
                <td className="px-3 py-1.5 text-text-dim">{s.posture_score.toFixed(0)}</td>
                <td className="px-3 py-1.5">
                  <SeverityBadge severity={s.risk_level} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Stage 10: pure aggregation of the capture's sessions into a per-endpoint view
// (backend/app/attack_surface/mapper.py) - nested in summary, no schema change needed.
function AttackSurfacePanel({ surface }) {
  return (
    <div className="border border-border bg-panel">
      <div className="px-3 py-2 border-b border-border-soft flex items-center justify-between flex-wrap gap-2">
        <span className="text-[11px] font-mono tracking-widest text-text-dim uppercase">
          Attack Surface ({surface.distinct_endpoints} endpoint{surface.distinct_endpoints === 1 ? "" : "s"})
        </span>
        <div className="flex items-center gap-3 text-[10px] font-mono text-text-faint">
          {surface.endpoints_with_deprecated_tls.length > 0 && (
            <span className="text-sev-high">
              {surface.endpoints_with_deprecated_tls.length} deprecated-TLS endpoint
              {surface.endpoints_with_deprecated_tls.length === 1 ? "" : "s"}
            </span>
          )}
          {surface.endpoints_with_plaintext_after_starttls.length > 0 && (
            <span className="text-sev-critical">
              {surface.endpoints_with_plaintext_after_starttls.length} STARTTLS-stripped endpoint
              {surface.endpoints_with_plaintext_after_starttls.length === 1 ? "" : "s"}
            </span>
          )}
        </div>
      </div>
      <table className="w-full text-[12px] font-mono border-collapse">
        <thead>
          <tr className="text-text-faint text-left border-b border-border-soft uppercase text-[10px] tracking-wider">
            <th className="px-3 py-1.5 font-medium">Endpoint</th>
            <th className="px-3 py-1.5 font-medium">Protocols</th>
            <th className="px-3 py-1.5 font-medium">Sessions</th>
            <th className="px-3 py-1.5 font-medium">Worst Risk</th>
            <th className="px-3 py-1.5 font-medium">Flags</th>
          </tr>
        </thead>
        <tbody>
          {surface.endpoints.map((e) => {
            const key = `${e.server_ip}:${e.server_port}`;
            return (
              <tr key={key} className="border-b border-border-soft last:border-b-0">
                <td className="px-3 py-1.5 text-text-dim">{key}</td>
                <td className="px-3 py-1.5 text-text-dim">{e.protocols_observed.join(", ")}</td>
                <td className="px-3 py-1.5 text-text-dim">{e.session_count}</td>
                <td className="px-3 py-1.5">
                  <SeverityBadge severity={e.worst_risk_level} />
                </td>
                <td className="px-3 py-1.5 text-[10px] text-text-faint">
                  {surface.endpoints_with_deprecated_tls.includes(key) && (
                    <span className="text-sev-high mr-2">deprecated TLS</span>
                  )}
                  {surface.endpoints_with_plaintext_after_starttls.includes(key) && (
                    <span className="text-sev-critical">STARTTLS stripped</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// Stage 11: report export links straight to backend/app/reports/router.py's
// download endpoints - plain <a> tags so the browser's own download handling takes
// over from the server's Content-Disposition: attachment header.
function ReportDownloads({ captureId }) {
  return (
    <div className="flex items-center gap-1 text-[10px] font-mono uppercase tracking-widest text-text-faint">
      <span>Report:</span>
      {["json", "html", "pdf"].map((format) => (
        <a
          key={format}
          href={getReportUrl(captureId, format)}
          className="border border-border px-2 py-1 hover:text-accent hover:border-accent"
        >
          {format}
        </a>
      ))}
    </div>
  );
}

function Breadcrumb({ filename }) {
  return (
    <div className="flex items-center gap-2 text-[11px] font-mono text-text-faint">
      <Link to="/" className="hover:text-accent">
        CAPTURES
      </Link>
      <span>/</span>
      <span className="text-text">{filename}</span>
    </div>
  );
}
