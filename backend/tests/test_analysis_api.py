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

    # Stage 9: ai_analysis is populated end-to-end once the committed models exist -
    # never a bare score, always backed by ranked SHAP-derived contributing features.
    ai_analysis = session["ai_analysis"]
    assert ai_analysis is not None
    assert ai_analysis["predicted_label"] == "weak"
    assert ai_analysis["top_contributing_features"]

    # Stage 10: crypto fingerprint is observable for a completed handshake.
    fingerprint = session["crypto_fingerprint"]
    assert fingerprint["observable"] is True
    assert len(fingerprint["fingerprint_id"]) == 16

    # Stage 10: no prior capture exists for this endpoint yet, so drift has no baseline.
    assert session["drift"]["status"] == "NO_BASELINE"

    # Stage 10: attack-surface map is nested in the capture-level summary.
    attack_surface = result["summary"]["attack_surface"]
    assert attack_surface["distinct_endpoints"] == 1
    assert attack_surface["findings_by_severity"]["HIGH"] >= 1

    # Every finding is now evidence-linked to a concrete field in the contract.
    assert all(finding["evidence_path"] for finding in session["findings"])


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


def test_second_capture_of_same_endpoint_detects_drift(dataset_dir):
    """Stage 10: uploading the same pcap twice hits the same server_ip/port/protocol
    twice, so the second capture's session should find the first as its baseline (with
    an identical configuration, so NO_DRIFT rather than NO_BASELINE).
    """
    pcap = dataset_dir / "01_tls10_3des_rsa.pcap"
    for _ in range(2):
        with open(pcap, "rb") as f:
            resp = client.post(
                "/api/analyses",
                files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
            )
        capture_id = resp.json()["capture_id"]

    result = client.get(f"/api/analyses/{capture_id}").json()
    assert result["sessions"][0]["drift"]["status"] == "NO_DRIFT"


def test_simulator_remediation_catalog_endpoint():
    resp = client.get("/api/simulator/remediations")
    assert resp.status_code == 200
    ids = {r["id"] for r in resp.json()["remediations"]}
    assert "upgrade_tls_version" in ids


def test_simulator_endpoint_simulates_remediation_for_real_session(dataset_dir):
    pcap = dataset_dir / "01_tls10_3des_rsa.pcap"
    with open(pcap, "rb") as f:
        create_resp = client.post(
            "/api/analyses",
            files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
        )
    capture_id = create_resp.json()["capture_id"]
    session_id = client.get(f"/api/analyses/{capture_id}").json()["sessions"][0]["session_id"]

    resp = client.post(
        f"/api/simulator/{capture_id}/sessions/{session_id}",
        json={"remediations": ["upgrade_tls_version", "remove_weak_cipher"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["after"]["posture_score"] > body["before"]["posture_score"]
    resolved_titles = {f["title"] for f in body["findings_resolved"]}
    assert "Deprecated TLS version negotiated" in resolved_titles


def test_simulator_endpoint_rejects_unknown_session():
    resp = client.post(
        "/api/simulator/does-not-exist/sessions/also-missing",
        json={"remediations": ["upgrade_tls_version"]},
    )
    assert resp.status_code == 404
