from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_create_analysis_runs_eagerly_and_completes(dataset_dir):
    """CELERY_TASK_ALWAYS_EAGER is forced on in conftest.py, so by the time POST returns
    the task has already run in-process - no separate worker/Redis needed for this test.
    """
    pcap = dataset_dir / "01_tls10_3des_rsa.pcap"

    with open(pcap, "rb") as f:
        resp = client.post(
            "/api/analyses",
            files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
        )

    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "COMPLETE"
    capture_id = body["capture_id"]

    get_resp = client.get(f"/api/analyses/{capture_id}")
    assert get_resp.status_code == 200
    result = get_resp.json()
    assert result["schema_version"] == "1.0"
    assert result["status"] == "COMPLETE"
    assert result["summary"]["capture_file"] == pcap.name
    assert result["summary"]["total_sessions_analyzed"] == 1
    assert result["summary"]["risk_level"] == "CRITICAL"

    session = result["sessions"][0]
    assert session["session_id"] == "SESS-SMTP-1"
    titles = {finding["title"] for finding in session["findings"]}
    assert "Deprecated TLS version negotiated" in titles
    assert session["risk_level"] == "CRITICAL"


def test_create_analysis_rejects_corrupt_file(tmp_path):
    bad_file = tmp_path / "not_a_pcap.bin"
    bad_file.write_bytes(b"this is definitely not a capture" * 10)

    with open(bad_file, "rb") as f:
        resp = client.post(
            "/api/analyses",
            files={"file": (bad_file.name, f, "application/octet-stream")},
        )

    assert resp.status_code == 422


def test_get_analysis_not_found_returns_404():
    resp = client.get("/api/analyses/does-not-exist")
    assert resp.status_code == 404


def test_list_analyses_includes_created_captures(dataset_dir):
    pcap = dataset_dir / "03_tls12_ecdhe_rsa_safe.pcap"
    with open(pcap, "rb") as f:
        create_resp = client.post(
            "/api/analyses",
            files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
        )
    capture_id = create_resp.json()["capture_id"]

    list_resp = client.get("/api/analyses")
    assert list_resp.status_code == 200
    ids = {entry["capture_id"] for entry in list_resp.json()["analyses"]}
    assert capture_id in ids


def test_multi_session_capture_produces_stable_session_ids(dataset_dir):
    pcap = dataset_dir / "22_multiple_sessions_combined.pcap"
    with open(pcap, "rb") as f:
        create_resp = client.post(
            "/api/analyses",
            files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
        )
    capture_id = create_resp.json()["capture_id"]

    result = client.get(f"/api/analyses/{capture_id}").json()
    assert result["summary"]["total_sessions_analyzed"] == 3
    session_ids = [s["session_id"] for s in result["sessions"]]
    assert len(session_ids) == len(set(session_ids))
