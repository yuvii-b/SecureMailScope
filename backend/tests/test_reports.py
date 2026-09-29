from fastapi.testclient import TestClient

from app.db import SessionLocal
from app.main import app
from app.models.analysis import Capture

client = TestClient(app)


def _create_completed_capture(dataset_dir, pcap_name: str) -> str:
    pcap = dataset_dir / pcap_name
    with open(pcap, "rb") as f:
        resp = client.post(
            "/api/analyses",
            files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
        )
    return resp.json()["capture_id"]


def test_report_json_matches_dashboard_contract(dataset_dir):
    capture_id = _create_completed_capture(dataset_dir, "01_tls10_3des_rsa.pcap")

    dashboard = client.get(f"/api/analyses/{capture_id}").json()
    report = client.get(f"/api/analyses/{capture_id}/report.json")

    assert report.status_code == 200
    assert "attachment" in report.headers["content-disposition"]
    body = report.json()
    # The report is a view of the same contract, plus report-only metadata.
    assert body["summary"] == dashboard["summary"]
    assert body["sessions"] == dashboard["sessions"]
    assert body["generated_at"]


def test_report_html_renders_findings_and_escapes_evidence(dataset_dir):
    capture_id = _create_completed_capture(dataset_dir, "14_starttls_plaintext_after_advertisement.pcap")

    resp = client.get(f"/api/analyses/{capture_id}/report.html")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    html = resp.text
    assert "SecureMailScope" in html
    assert "STARTTLS" in html
    # Stage 6's plaintext-after-STARTTLS finding leaks a real IMAP LOGIN command as
    # evidence - Jinja2 autoescaping must still be on for arbitrary packet-derived text.
    assert "LOGIN" in html
    assert "<script>" not in html


def test_report_pdf_either_renders_or_reports_missing_native_deps(dataset_dir):
    capture_id = _create_completed_capture(dataset_dir, "01_tls10_3des_rsa.pcap")

    resp = client.get(f"/api/analyses/{capture_id}/report.pdf")
    if resp.status_code == 200:
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.content.startswith(b"%PDF")
    else:
        assert resp.status_code == 503
        assert "WeasyPrint" in resp.json()["detail"]


def test_report_endpoints_404_for_unknown_capture():
    for ext in ("json", "html", "pdf"):
        resp = client.get(f"/api/analyses/does-not-exist/report.{ext}")
        assert resp.status_code == 404


def test_report_endpoints_409_while_capture_not_complete():
    db = SessionLocal()
    try:
        capture = Capture(filename="pending.pcap", status="RUNNING")
        db.add(capture)
        db.commit()
        db.refresh(capture)
        capture_id = capture.id
    finally:
        db.close()

    for ext in ("json", "html", "pdf"):
        resp = client.get(f"/api/analyses/{capture_id}/report.{ext}")
        assert resp.status_code == 409
