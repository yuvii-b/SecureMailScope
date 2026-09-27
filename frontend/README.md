# SecureMailScope frontend (Stage 8)

React + JavaScript (JSX) + Tailwind + Recharts dashboard consuming the backend's
`/api/analyses` JSON contract (see `../CLAUDE.md` §7). Dense, dark, technical UI in the
style of network-analysis tooling (Wireshark/SIEM dashboards) rather than a generic SaaS
look. Plain JS on purpose - no TypeScript/build-time type checking, so the contract in
`src/api/client.js` is trusted at runtime rather than enforced at compile time.

```bash
npm install
npm run dev
```

The dev server proxies `/api/*` to `http://127.0.0.1:8000` (see `vite.config.js`) - run the
backend (`cd ../backend && uvicorn app.main:app --reload`) alongside it.

Pages (`src/pages/`):

- `CapturesListPage` - upload a `.pcap`/`.pcapng` and list all analyzed captures.
- `CaptureDashboardPage` - one capture's posture score, findings-by-severity chart, and
  session table.
- `SessionDetailPage` - one session's STARTTLS/TLS handshake/certificate evidence and
  findings, drilled down from the dashboard.
