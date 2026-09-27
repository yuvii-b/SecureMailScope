import { useRef, useState } from "react";
import { uploadCapture } from "../api/client";

export function UploadPanel({ onUploaded }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleFile(file) {
    setBusy(true);
    setError(null);
    try {
      const res = await uploadCapture(file);
      onUploaded(res.capture_id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "upload failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files?.[0];
        if (file) handleFile(file);
      }}
      className={`border border-dashed px-4 py-3 flex items-center gap-3 transition-colors ${
        dragging ? "border-accent bg-accent/5" : "border-border bg-panel"
      }`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) handleFile(file);
          e.target.value = "";
        }}
      />
      <span className="font-mono text-[11px] text-text-dim uppercase tracking-wider">
        {busy ? "uploading + analyzing..." : "drop a .pcap / .pcapng capture, or"}
      </span>
      <button
        onClick={() => inputRef.current?.click()}
        disabled={busy}
        className="px-2.5 py-1 text-[12px] font-mono border border-accent/50 text-accent bg-accent/10 hover:bg-accent/20 disabled:opacity-40"
      >
        BROWSE
      </button>
      {error && <span className="text-[11px] font-mono text-sev-critical">{error}</span>}
    </div>
  );
}
