import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getCapture } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";

function Field({ label, value }) {
  const display =
    value === null || value === undefined
      ? "—"
      : typeof value === "boolean"
        ? value
          ? "true"
          : "false"
        : String(value);
  return (
    <div className="flex justify-between gap-4 py-1 border-b border-border-soft last:border-b-0">
      <span className="text-text-faint text-[11px] uppercase tracking-wider">{label}</span>
      <span className="text-text font-mono text-[12px] text-right break-all">{display}</span>
    </div>
  );
}

function Panel({ title, children }) {
  return (
    <div className="border border-border bg-panel">
      <div className="px-3 py-2 border-b border-border-soft">
        <span className="text-[11px] font-mono tracking-widest text-text-dim uppercase">{title}</span>
      </div>
      <div className="px-3 py-1.5">{children}</div>
    </div>
  );
}

export function SessionDetailPage() {
  const { captureId, sessionId } = useParams();
  const [capture, setCapture] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!captureId) return;
    getCapture(captureId)
      .then((res) => {
        if ("sessions" in res) setCapture(res);
        else setError("capture not yet complete");
      })
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load"));
  }, [captureId]);

  if (error) return <div className="p-4 text-sev-critical font-mono text-[12px]">{error}</div>;
  if (!capture) return <div className="p-4 text-text-faint font-mono text-[12px]">loading...</div>;

  const session = capture.sessions.find((s) => s.session_id === sessionId);
  if (!session) return <div className="p-4 text-sev-critical font-mono text-[12px]">session not found</div>;

  const { starttls_negotiation: sn, tls_handshake: tls, certificate: cert } = session;

  return (
    <div className="p-4 max-w-[1400px] w-full mx-auto flex flex-col gap-4">
      <div className="flex items-center gap-2 text-[11px] font-mono text-text-faint">
        <Link to="/" className="hover:text-accent">
          CAPTURES
        </Link>
        <span>/</span>
        <Link to={`/captures/${captureId}`} className="hover:text-accent">
          {capture.summary.capture_file}
        </Link>
        <span>/</span>
        <span className="text-text">{session.session_id}</span>
      </div>

      <div className="border border-border bg-panel p-4 flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-3">
          <span className="font-mono text-[15px] font-bold text-text">{session.session_id}</span>
          <span className="font-mono text-[12px] text-text-dim">
            {session.protocol} &middot; {session.client.ip}:{session.client.port} &rarr; {session.server.ip}:
            {session.server.port}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="font-mono text-[12px] text-text-dim">
            posture <span className="text-text font-bold">{session.posture_score.toFixed(0)}</span>/100
          </span>
          <SeverityBadge severity={session.risk_level} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Panel title="STARTTLS Negotiation">
          <Field label="status" value={sn.status} />
          <Field label="command detected" value={sn.command_detected} />
          <Field label="evidence" value={sn.evidence} />
        </Panel>

        <Panel title="TLS Handshake">
          <Field label="observed" value={tls.handshake_observed} />
          <Field label="version negotiated" value={tls.version_negotiated} />
          <Field label="cipher suite" value={tls.cipher_suite_selected} />
          <Field label="key exchange" value={tls.key_exchange} />
          <Field label="forward secrecy" value={tls.forward_secrecy} />
          <Field label="SNI" value={tls.sni} />
          <Field label="certificates observed" value={tls.certificate_count} />
        </Panel>

        <Panel title="Certificate">
          <Field label="subject" value={cert.subject} />
          <Field label="issuer" value={cert.issuer} />
          <Field label="key algorithm" value={cert.key_algorithm} />
          <Field label="key length (bits)" value={cert.key_length_bits} />
          <Field label="signature algorithm" value={cert.signature_algorithm} />
          <Field label="chain status" value={cert.chain_status} />
          <Field label="self-signed" value={cert.self_signed} />
          <Field label="expired" value={cert.expired} />
          <Field label="hostname match" value={cert.hostname_match} />
          <Field label="fingerprint (SHA-256)" value={cert.sha256_fingerprint} />
        </Panel>
      </div>

      {(tls.alerts.length > 0 || tls.notes.length > 0 || cert.notes.length > 0) && (
        <Panel title="Notes / Alerts">
          <div className="flex flex-col gap-1 py-1 text-[12px] font-mono text-text-dim">
            {tls.alerts.map((a, i) => (
              <div key={`a${i}`} className="text-sev-high">
                alert: {a}
              </div>
            ))}
            {[...tls.notes, ...cert.notes].map((n, i) => (
              <div key={`n${i}`}>note: {n}</div>
            ))}
          </div>
        </Panel>
      )}

      <div className="border border-border bg-panel">
        <div className="px-3 py-2 border-b border-border-soft">
          <span className="text-[11px] font-mono tracking-widest text-text-dim uppercase">
            Findings ({session.findings.length})
          </span>
        </div>
        {session.findings.length === 0 ? (
          <div className="px-3 py-6 text-center text-text-faint font-mono text-[12px]">
            no findings for this session
          </div>
        ) : (
          <div className="divide-y divide-border-soft">
            {session.findings.map((f, i) => (
              <div key={i} className="px-3 py-2.5 flex flex-col gap-1">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <span className="font-mono text-[12px] font-semibold text-text">{f.title}</span>
                  <span className="ml-auto text-[10px] font-mono text-text-faint uppercase">{f.domain}</span>
                </div>
                <div className="text-[11px] font-mono text-text-dim pl-0.5">
                  <span className="text-text-faint">evidence:</span> {f.evidence}
                </div>
                <div className="text-[11px] font-mono text-text-dim pl-0.5">
                  <span className="text-text-faint">policy:</span> {f.policy_reference}
                </div>
                <div className="text-[11px] font-mono text-sev-ok pl-0.5">
                  <span className="text-text-faint">recommendation:</span> {f.recommendation}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
