from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_upload_valid_pcap(dataset_dir):
    pcap = dataset_dir / "03_tls12_ecdhe_rsa_safe.pcap"

    with open(pcap, "rb") as f:
        resp = client.post(
            "/api/pcap/upload",
            files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["format"] == "pcap"
    assert body["flow_count"] == 1
    assert body["flows"][0]["transport"] == "TCP"


def test_upload_multiple_sessions(dataset_dir):
    pcap = dataset_dir / "22_multiple_sessions_combined.pcap"

    with open(pcap, "rb") as f:
        resp = client.post(
            "/api/pcap/upload",
            files={"file": (pcap.name, f, "application/octet-stream")},
        )

    assert resp.status_code == 200
    assert resp.json()["flow_count"] == 3


def test_upload_corrupt_file_returns_422(tmp_path):
    bad_file = tmp_path / "not_a_pcap.bin"
    bad_file.write_bytes(b"this is definitely not a capture" * 10)

    with open(bad_file, "rb") as f:
        resp = client.post(
            "/api/pcap/upload",
            files={"file": (bad_file.name, f, "application/octet-stream")},
        )

    assert resp.status_code == 422
    assert "Unrecognized file signature" in resp.json()["detail"]


def test_upload_empty_file_returns_422(tmp_path):
    empty_file = tmp_path / "empty.pcap"
    empty_file.write_bytes(b"")

    with open(empty_file, "rb") as f:
        resp = client.post(
            "/api/pcap/upload",
            files={"file": (empty_file.name, f, "application/octet-stream")},
        )

    assert resp.status_code == 422


def test_sessions_endpoint_reassembles_and_identifies_protocol(dataset_dir):
    pcap = dataset_dir / "03_tls12_ecdhe_rsa_safe.pcap"

    with open(pcap, "rb") as f:
        resp = client.post(
            "/api/pcap/sessions",
            files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["session_count"] == 1
    session = body["sessions"][0]
    assert session["protocol"] == "SMTP"
    assert session["server"]["port"] == 25


def test_sessions_endpoint_includes_starttls_and_tls_handshake(dataset_dir):
    pcap = dataset_dir / "03_tls12_ecdhe_rsa_safe.pcap"

    with open(pcap, "rb") as f:
        resp = client.post(
            "/api/pcap/sessions",
            files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
        )

    assert resp.status_code == 200
    session = resp.json()["sessions"][0]
    assert session["starttls"]["status"] == "SUCCESS"
    assert session["tls_handshake"]["version_negotiated"] == "TLS 1.2"
    assert session["tls_handshake"]["cipher_suite_selected"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert session["tls_handshake"]["forward_secrecy"] is True


def test_sessions_endpoint_includes_certificate_analysis(dataset_dir):
    pcap = dataset_dir / "03_tls12_ecdhe_rsa_safe.pcap"

    with open(pcap, "rb") as f:
        resp = client.post(
            "/api/pcap/sessions",
            files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
        )

    assert resp.status_code == 200
    session = resp.json()["sessions"][0]
    assert session["certificate"]["subject"] == "mail.example.test"
    assert session["certificate"]["expired"] is False
    assert session["certificate"]["hostname_match"] is True
    assert session["certificate"]["chain_status"] == "OBSERVED_VALID"


def test_sessions_endpoint_reports_incomplete_chain(dataset_dir):
    pcap = dataset_dir / "13_cert_incomplete_chain.pcap"

    with open(pcap, "rb") as f:
        resp = client.post(
            "/api/pcap/sessions",
            files={"file": (pcap.name, f, "application/vnd.tcpdump.pcap")},
        )

    assert resp.status_code == 200
    session = resp.json()["sessions"][0]
    assert session["certificate"]["chain_status"] == "NOT_OBSERVABLE"


def test_sessions_endpoint_rejects_corrupt_file(tmp_path):
    bad_file = tmp_path / "not_a_pcap.bin"
    bad_file.write_bytes(b"this is definitely not a capture" * 10)

    with open(bad_file, "rb") as f:
        resp = client.post(
            "/api/pcap/sessions",
            files={"file": (bad_file.name, f, "application/octet-stream")},
        )

    assert resp.status_code == 422
