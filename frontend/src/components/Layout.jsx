import { Link, useLocation } from "react-router-dom";

export function Layout({ children }) {
  const location = useLocation();
  const onDashboard = location.pathname === "/";

  return (
    <div className="min-h-full flex flex-col">
      <header className="border-b border-border bg-panel">
        <div className="flex items-center h-12 px-4 gap-3">
          <Link to="/" className="flex items-center gap-2 shrink-0">
            <span className="w-2 h-2 bg-accent shadow-[0_0_6px_var(--color-accent)]" />
            <span className="font-mono font-bold tracking-tight text-text text-[14px]">
              SecureMailScope
            </span>
          </Link>
          <span className="text-text-faint text-[11px] font-mono hidden sm:inline">
            passive TLS/X.509 posture analyzer
          </span>
          <nav className="ml-auto flex items-center gap-1">
            <Link
              to="/"
              className={`px-2.5 py-1 text-[12px] font-mono border ${
                onDashboard
                  ? "border-accent/50 text-accent bg-accent/10"
                  : "border-transparent text-text-dim hover:text-text hover:border-border"
              }`}
            >
              CAPTURES
            </Link>
          </nav>
        </div>
      </header>
      <main className="flex-1 flex flex-col">{children}</main>
      <footer className="border-t border-border-soft px-4 py-1.5 text-[10px] text-text-faint font-mono flex justify-between">
        <span>schema v1.0 &middot; passive analysis engine never touches live servers</span>
        <span>SIH 2026</span>
      </footer>
    </div>
  );
}
