"""Stage 12: full-dataset integration run producing CLAUDE.md §11's demo metrics, plus a
set of pre-generated JSON/HTML(/PDF) reports to fall back on if live upload fails during
the actual SIH demo.

Runs standalone against every pcap in securemail_test_pcaps/ - no API, no DB, no running
server - straight through `api.pipeline.analyze_pcap_file()`, the exact same function
`POST /api/analyses` calls. These numbers describe the shipped pipeline (Stages 2-10),
not a separate demo-only code path.

Usage (from backend/):  ../.venv/Scripts/python.exe scripts/demo_metrics.py

Writes:
  backend/demo_assets/metrics.json         - machine-readable metrics
  backend/demo_assets/metrics.md           - human-readable summary table
  backend/demo_assets/reports/<file>.json  - one full report per scenario
  backend/demo_assets/reports/<file>.html  - "
  backend/demo_assets/reports/<file>.pdf   - " (only if WeasyPrint's native deps
                                              are installed in this environment)
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from scapy.utils import rdpcap  # noqa: E402

from app.api.pipeline import analyze_pcap_file  # noqa: E402
from app.ml.dataset import SESSION_LABEL_OVERRIDES, label_by_file  # noqa: E402
from app.reports.renderer import render_html, render_pdf  # noqa: E402

REPO_ROOT = _BACKEND_ROOT.parent
DATASET_DIR = REPO_ROOT / "securemail_test_pcaps"
OUTPUT_DIR = _BACKEND_ROOT / "demo_assets"
REPORTS_DIR = OUTPUT_DIR / "reports"

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _ground_truth_labels(filename: str, n_sessions: int, labels_by_file: dict) -> list:
    """Same per-session labeling `ml/dataset.py` trains on, including file 22's
    positional per-session override - so accuracy is scored against the actual ground
    truth used, not a blanket per-file label that would be wrong for that one file.
    """
    override = SESSION_LABEL_OVERRIDES.get(filename)
    if override is not None:
        return override
    return [labels_by_file.get(filename)] * n_sessions


def _write_backup_report(contract: dict, stem: str, pdf_available: bool) -> bool:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report_data = {**contract, "capture_id": stem, "status": "COMPLETE", "completed_at": now, "generated_at": now}

    (REPORTS_DIR / f"{stem}.json").write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    (REPORTS_DIR / f"{stem}.html").write_text(render_html(report_data), encoding="utf-8")

    if pdf_available:
        try:
            (REPORTS_DIR / f"{stem}.pdf").write_bytes(render_pdf(report_data))
        except (ImportError, OSError):
            return False  # stop retrying PDF for the rest of the run - same env for all files
    return pdf_available


def run() -> dict:
    labels_by_file = label_by_file(DATASET_DIR)
    pcap_paths = sorted(DATASET_DIR.glob("*.pcap"))
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    per_file = []
    protocol_counts: dict = {}
    findings_totals = {s: 0 for s in SEVERITIES}
    total_packets = total_bytes = total_sessions = 0
    total_tls_sessions = total_certs = total_anomalous = 0
    correct_predictions = labeled_sessions = 0
    pdf_available = True

    total_start = time.perf_counter()
    for pcap_path in pcap_paths:
        file_size = pcap_path.stat().st_size
        packet_count = len(rdpcap(str(pcap_path)))

        start = time.perf_counter()
        contract = analyze_pcap_file(pcap_path, pcap_path.name)
        elapsed = time.perf_counter() - start

        sessions = contract["sessions"]
        ground_truth = _ground_truth_labels(pcap_path.name, len(sessions), labels_by_file)

        file_findings = {s: 0 for s in SEVERITIES}
        tls_sessions = certs_extracted = anomalous = 0

        for session, truth in zip(sessions, ground_truth):
            protocol_counts[session["protocol"]] = protocol_counts.get(session["protocol"], 0) + 1
            if session["tls_handshake"].get("handshake_observed"):
                tls_sessions += 1
            if session["certificate"].get("subject") is not None:
                certs_extracted += 1
            for f in session["findings"]:
                file_findings[f["severity"]] += 1
                findings_totals[f["severity"]] += 1
            ai = session.get("ai_analysis")
            if ai:
                if ai.get("anomaly_flag"):
                    anomalous += 1
                if truth is not None:
                    labeled_sessions += 1
                    correct_predictions += ai.get("predicted_label") == truth

        total_packets += packet_count
        total_bytes += file_size
        total_sessions += len(sessions)
        total_tls_sessions += tls_sessions
        total_certs += certs_extracted
        total_anomalous += anomalous

        per_file.append({
            "filename": pcap_path.name,
            "file_size_bytes": file_size,
            "packet_count": packet_count,
            "sessions_reconstructed": len(sessions),
            "protocols": sorted({s["protocol"] for s in sessions}),
            "tls_sessions_detected": tls_sessions,
            "certificates_extracted": certs_extracted,
            "findings_by_severity": file_findings,
            "anomalous_sessions": anomalous,
            "overall_risk_level": contract["summary"]["risk_level"],
            "overall_health_score": contract["summary"]["overall_health_score"],
            "analysis_time_seconds": round(elapsed, 4),
        })

        pdf_available = _write_backup_report(contract, pcap_path.stem, pdf_available)

    total_elapsed = time.perf_counter() - total_start
    accuracy = (correct_predictions / labeled_sessions) if labeled_sessions else None

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files_analyzed": len(pcap_paths),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "total_sessions_reconstructed": total_sessions,
        "sessions_by_protocol": protocol_counts,
        "tls_sessions_detected": total_tls_sessions,
        "certificates_extracted": total_certs,
        "findings_by_severity": findings_totals,
        "anomalous_sessions_flagged": total_anomalous,
        "ai_label_accuracy_on_training_set": accuracy,
        "accuracy_note": (
            "Compares ai_analysis.predicted_label against the same manifest ground truth "
            "the model was trained on (app/ml/dataset.py) - a training-set sanity check, "
            "not a held-out generalization measurement, for the same reason Stage 9's own "
            "notes give: ~26 labeled sessions is a pipeline demonstration, not a claim of "
            "generalization."
        ),
        "pdf_backup_generated": pdf_available,
        "total_analysis_time_seconds": round(total_elapsed, 3),
        "per_file": per_file,
    }


def _write_markdown(summary: dict, path: Path) -> None:
    lines = [
        "# SecureMailScope — Demo Metrics",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Totals",
        "",
        f"- Files analyzed: {summary['files_analyzed']}",
        f"- Total packets: {summary['total_packets']}",
        f"- Total capture bytes: {summary['total_bytes']}",
        f"- TCP sessions reconstructed: {summary['total_sessions_reconstructed']}",
        f"- Sessions by protocol: {summary['sessions_by_protocol']}",
        f"- TLS sessions detected: {summary['tls_sessions_detected']}",
        f"- Certificates extracted: {summary['certificates_extracted']}",
        f"- Findings by severity: {summary['findings_by_severity']}",
        f"- Anomalous sessions flagged: {summary['anomalous_sessions_flagged']}",
        f"- AI label accuracy (training set): {summary['ai_label_accuracy_on_training_set']}",
        f"- PDF backups generated: {summary['pdf_backup_generated']}",
        f"- Total analysis time: {summary['total_analysis_time_seconds']}s",
        "",
        "## Per-file",
        "",
        "| File | Packets | Sessions | Protocols | TLS | Certs | Findings (C/H/M/L/I) | Risk | Score | Time (s) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for f in summary["per_file"]:
        fs = f["findings_by_severity"]
        lines.append(
            f"| {f['filename']} | {f['packet_count']} | {f['sessions_reconstructed']} | "
            f"{', '.join(f['protocols'])} | {f['tls_sessions_detected']} | "
            f"{f['certificates_extracted']} | "
            f"{fs['CRITICAL']}/{fs['HIGH']}/{fs['MEDIUM']}/{fs['LOW']}/{fs['INFO']} | "
            f"{f['overall_risk_level']} | {f['overall_health_score']} | "
            f"{f['analysis_time_seconds']} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    summary = run()
    (OUTPUT_DIR / "metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    _write_markdown(summary, OUTPUT_DIR / "metrics.md")

    print(
        f"files_analyzed={summary['files_analyzed']} "
        f"total_packets={summary['total_packets']} "
        f"total_sessions={summary['total_sessions_reconstructed']} "
        f"findings={summary['findings_by_severity']} "
        f"accuracy={summary['ai_label_accuracy_on_training_set']} "
        f"pdf_backup_generated={summary['pdf_backup_generated']} "
        f"time={summary['total_analysis_time_seconds']}s"
    )
    print(f"Wrote {OUTPUT_DIR / 'metrics.json'} and {OUTPUT_DIR / 'metrics.md'}")
    print(f"Wrote per-scenario backup reports to {REPORTS_DIR}")
