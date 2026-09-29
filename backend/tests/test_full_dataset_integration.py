"""Stage 12: full-dataset integration run through the real FastAPI app.

Every earlier stage's tests exercise a handful of scenario files chosen to hit one
specific code path; this is the one place that uploads *every* genny.py pcap through
`POST /api/analyses` end-to-end and checks the whole pipeline holds together across the
full dataset at once, matching CLAUDE.md Stage 12's "full run against every genny.py
scenario" requirement.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_full_dataset_analyzes_successfully_end_to_end(dataset_dir):
    pcap_paths = sorted(dataset_dir.glob("*.pcap"))
    # CLAUDE.md's "22 scenario files" spans 24 actual pcaps: scenario 14
    # (STARTTLS failure modes) is split across 3 separate files.
    assert len(pcap_paths) == 24

    for pcap_path in pcap_paths:
        with open(pcap_path, "rb") as f:
            resp = client.post(
                "/api/analyses",
                files={"file": (pcap_path.name, f, "application/vnd.tcpdump.pcap")},
            )
        assert resp.status_code == 202, f"{pcap_path.name}: upload failed: {resp.text}"
        body = resp.json()
        assert body["status"] == "COMPLETE", f"{pcap_path.name}: {body}"
        capture_id = body["capture_id"]

        result = client.get(f"/api/analyses/{capture_id}").json()
        assert result["status"] == "COMPLETE"
        assert result["schema_version"] == "1.0"
        assert result["summary"]["total_sessions_analyzed"] >= 1, pcap_path.name
        assert result["summary"]["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

        for session in result["sessions"]:
            assert session["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
            # Stages 9/10 are additive to every session regardless of scenario - never
            # silently missing, even for files 19/21's deliberately unidentifiable traffic.
            assert session["ai_analysis"] is not None, f"{pcap_path.name}/{session['session_id']}"
            assert session["crypto_fingerprint"] is not None
            assert session["drift"] is not None
            assert all(finding["evidence_path"] for finding in session["findings"])

        # The report export routes (Stage 11) work for every scenario too, not just the
        # handful test_reports.py exercises directly.
        for ext in ("json", "html"):
            report_resp = client.get(f"/api/analyses/{capture_id}/report.{ext}")
            assert report_resp.status_code == 200, f"{pcap_path.name} report.{ext}"
