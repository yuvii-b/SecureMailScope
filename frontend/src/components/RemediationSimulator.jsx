import { useEffect, useState } from "react";
import { getRemediationCatalog, simulateRemediation } from "../api/client";
import { SeverityBadge } from "./SeverityBadge";

// Stage 10: "what would the posture score/findings become if I fixed X" - reruns the
// same deterministic rule engine used for real analysis against a hypothetically-patched
// copy of this session's tls_handshake/certificate/starttls dicts. Nothing here is sent
// to a real mail server (backend/app/simulator/remediation.py).
export function RemediationSimulator({ captureId, sessionId }) {
  const [catalog, setCatalog] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    getRemediationCatalog()
      .then((res) => setCatalog(res.remediations))
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load remediation catalog"));
  }, []);

  function toggle(id) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function runSimulation() {
    if (selected.size === 0) return;
    setLoading(true);
    setError(null);
    simulateRemediation(captureId, sessionId, [...selected])
      .then(setResult)
      .catch((e) => setError(e instanceof Error ? e.message : "simulation failed"))
      .finally(() => setLoading(false));
  }

  return (
    <div className="border border-border bg-panel">
      <div className="px-3 py-2 border-b border-border-soft">
        <span className="text-[11px] font-mono tracking-widest text-text-dim uppercase">
          What-If Remediation Simulator
        </span>
      </div>

      <div className="px-3 py-2.5 flex flex-col gap-2">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5">
          {catalog.map((r) => (
            <label key={r.id} className="flex items-start gap-2 cursor-pointer group">
              <input
                type="checkbox"
                checked={selected.has(r.id)}
                onChange={() => toggle(r.id)}
                className="mt-0.5 accent-accent"
              />
              <span className="flex flex-col">
                <span className="font-mono text-[12px] text-text group-hover:text-accent">{r.title}</span>
                <span className="font-mono text-[10px] text-text-faint">{r.description}</span>
              </span>
            </label>
          ))}
        </div>

        <div className="flex items-center gap-2 pt-1">
          <button
            onClick={runSimulation}
            disabled={selected.size === 0 || loading}
            className="px-3 py-1.5 text-[11px] font-mono font-semibold tracking-wide border border-accent-dim bg-accent-dim/10 text-accent disabled:opacity-40 disabled:cursor-not-allowed hover:bg-accent-dim/20"
          >
            {loading ? "SIMULATING..." : "SIMULATE"}
          </button>
          {error && <span className="text-[11px] font-mono text-sev-critical">{error}</span>}
        </div>
      </div>

      {result && (
        <div className="border-t border-border-soft px-3 py-2.5 flex flex-col gap-3">
          <div className="flex items-center gap-4">
            <span className="font-mono text-[12px] text-text-dim">
              posture <span className="text-text font-bold">{result.before.posture_score.toFixed(0)}</span>
              {" -> "}
              <span className="text-sev-ok font-bold">{result.after.posture_score.toFixed(0)}</span>/100
            </span>
            <span
              className={`font-mono text-[12px] font-bold ${
                result.posture_score_delta > 0 ? "text-sev-ok" : "text-text-faint"
              }`}
            >
              {result.posture_score_delta > 0 ? "+" : ""}
              {result.posture_score_delta}
            </span>
            <SeverityBadge severity={result.before.risk_level} />
            <span className="text-text-faint">&rarr;</span>
            <SeverityBadge severity={result.after.risk_level} />
          </div>

          <FindingDeltaList title="resolved" findings={result.findings_resolved} tone="text-sev-ok" />
          <FindingDeltaList title="remaining" findings={result.findings_remaining} tone="text-text-dim" />
          <FindingDeltaList
            title="newly introduced"
            findings={result.findings_newly_introduced}
            tone="text-sev-critical"
          />
        </div>
      )}
    </div>
  );
}

function FindingDeltaList({ title, findings, tone }) {
  if (findings.length === 0) return null;
  return (
    <div className="flex flex-col gap-1">
      <span className={`text-[10px] font-mono uppercase tracking-wider ${tone}`}>
        {title} ({findings.length})
      </span>
      <div className="flex flex-col gap-1">
        {findings.map((f, i) => (
          <div key={i} className="flex items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <span className="font-mono text-[11px] text-text-dim">{f.title}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
