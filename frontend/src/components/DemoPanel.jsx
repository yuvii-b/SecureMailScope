import { useState } from "react";
import { uploadCapture } from "../api/client";

// Quick-demo buttons for live presentations: each fetches a pre-bundled pcap from
// frontend/public/demo-pcaps/ (a static asset, not the backend) and feeds it through the
// exact same uploadCapture() flow the drag-and-drop UploadPanel uses, so clicking one
// still exercises the real upload -> analyze path end-to-end - it just skips the OS file
// picker, which is the part that's awkward to click through live on stage.
const DEMOS = [
  {
    label: "Critical",
    file: "01_tls10_3des_rsa.pcap",
    blurb: "TLS 1.0 + 3DES, self-signed cert",
  },
  {
    label: "Best available",
    file: "03_tls12_ecdhe_rsa_safe.pcap",
    blurb: "TLS 1.2 ECDHE + AES-GCM, forward secrecy",
  },
  {
    label: "Credential leak",
    file: "14_starttls_plaintext_after_advertisement.pcap",
    blurb: "STARTTLS stripped, plaintext IMAP LOGIN",
  },
];

export function DemoPanel({ onUploaded }) {
  const [busyFile, setBusyFile] = useState(null);
  const [error, setError] = useState(null);

  async function runDemo(demo) {
    setBusyFile(demo.file);
    setError(null);
    try {
      const res = await fetch(`/demo-pcaps/${demo.file}`);
      if (!res.ok) throw new Error(`could not load bundled demo pcap: ${demo.file}`);
      const blob = await res.blob();
      const file = new File([blob], demo.file, { type: "application/vnd.tcpdump.pcap" });
      const uploaded = await uploadCapture(file);
      onUploaded(uploaded.capture_id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "demo run failed");
    } finally {
      setBusyFile(null);
    }
  }

  return (
    <div className="border border-border bg-panel px-4 py-3 flex items-center gap-3 flex-wrap">
      <span className="font-mono text-[11px] text-text-dim uppercase tracking-wider">Quick demo:</span>
      {DEMOS.map((demo) => (
        <button
          key={demo.file}
          onClick={() => runDemo(demo)}
          disabled={busyFile !== null}
          title={demo.blurb}
          className="px-2.5 py-1 text-[12px] font-mono border border-accent/50 text-accent bg-accent/10 hover:bg-accent/20 disabled:opacity-40"
        >
          {busyFile === demo.file ? "ANALYZING..." : demo.label.toUpperCase()}
        </button>
      ))}
      {error && <span className="text-[11px] font-mono text-sev-critical">{error}</span>}
    </div>
  );
}
