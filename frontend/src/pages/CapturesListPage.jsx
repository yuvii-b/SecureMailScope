import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listCaptures } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { SeverityBadge } from "../components/SeverityBadge";
import { UploadPanel } from "../components/UploadPanel";

function formatTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export function CapturesListPage() {
  const [captures, setCaptures] = useState(null);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  function refresh() {
    listCaptures()
      .then((res) => setCaptures(res.analyses))
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load"));
  }

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex-1 flex flex-col p-4 gap-4 max-w-[1400px] w-full mx-auto">
      <UploadPanel onUploaded={(id) => navigate(`/captures/${id}`)} />

      {error && <div className="text-sev-critical font-mono text-[12px]">{error}</div>}

      <div className="border border-border bg-panel">
        <div className="px-3 py-2 border-b border-border-soft flex items-center justify-between">
          <span className="text-[11px] font-mono tracking-widest text-text-dim uppercase">
            Captures {captures ? `(${captures.length})` : ""}
          </span>
        </div>
        <table className="w-full text-[12px] font-mono border-collapse">
          <thead>
            <tr className="text-text-faint text-left border-b border-border-soft uppercase text-[10px] tracking-wider">
              <th className="px-3 py-1.5 font-medium">File</th>
              <th className="px-3 py-1.5 font-medium">Status</th>
              <th className="px-3 py-1.5 font-medium">Sessions</th>
              <th className="px-3 py-1.5 font-medium">Score</th>
              <th className="px-3 py-1.5 font-medium">Risk</th>
              <th className="px-3 py-1.5 font-medium">Created</th>
            </tr>
          </thead>
          <tbody>
            {captures?.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-text-faint">
                  no captures analyzed yet
                </td>
              </tr>
            )}
            {captures?.map((c) => (
              <tr
                key={c.capture_id}
                onClick={() => navigate(`/captures/${c.capture_id}`)}
                className="border-b border-border-soft hover:bg-panel-alt cursor-pointer"
              >
                <td className="px-3 py-1.5 text-text">{c.filename}</td>
                <td className="px-3 py-1.5">
                  <StatusBadge status={c.status} />
                </td>
                <td className="px-3 py-1.5 text-text-dim">
                  {c.summary?.total_sessions_analyzed ?? "—"}
                </td>
                <td className="px-3 py-1.5 text-text-dim">
                  {c.summary ? c.summary.overall_health_score.toFixed(1) : "—"}
                </td>
                <td className="px-3 py-1.5">
                  {c.summary ? <SeverityBadge severity={c.summary.risk_level} /> : "—"}
                </td>
                <td className="px-3 py-1.5 text-text-faint">{formatTime(c.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
