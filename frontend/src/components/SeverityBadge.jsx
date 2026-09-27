const COLORS = {
  CRITICAL: "text-sev-critical border-sev-critical/40 bg-sev-critical/10",
  HIGH: "text-sev-high border-sev-high/40 bg-sev-high/10",
  MEDIUM: "text-sev-medium border-sev-medium/40 bg-sev-medium/10",
  LOW: "text-sev-low border-sev-low/40 bg-sev-low/10",
  INFO: "text-sev-info border-sev-info/40 bg-sev-info/10",
};

export function SeverityBadge({ severity }) {
  const cls = COLORS[severity] ?? COLORS.INFO;
  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 text-[11px] font-semibold tracking-wide border ${cls} font-mono`}
    >
      {severity}
    </span>
  );
}
