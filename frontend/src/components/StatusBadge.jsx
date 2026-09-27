const COLORS = {
  PENDING: "text-sev-info border-sev-info/40 bg-sev-info/10",
  RUNNING: "text-sev-low border-sev-low/40 bg-sev-low/10",
  COMPLETE: "text-sev-ok border-sev-ok/40 bg-sev-ok/10",
  FAILED: "text-sev-critical border-sev-critical/40 bg-sev-critical/10",
};

export function StatusBadge({ status }) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-[11px] font-semibold tracking-wide border font-mono ${COLORS[status]}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {status}
    </span>
  );
}
