"""genny.py's dataset has no two fixture files sharing a server endpoint (every scenario
uses a distinct synthetic server_ip - see CLAUDE.md §5/Stage 10), so there is no natural
"same mail server observed twice with a different config" pair to drive a realistic
before/after pcap pair. `detect_drift()` is therefore tested with hand-built dicts (the
same pattern `test_certificates.py` uses for the CHAIN_INVALID case genny.py doesn't
otherwise produce); `find_baseline_and_compare()` is tested by hand-inserting two
Capture/SessionRecord rows that share an endpoint directly into the test DB.
"""
from datetime import datetime, timezone

from app.db import SessionLocal
from app.drift.detector import (
    STATUS_DRIFT_DETECTED,
    STATUS_NO_BASELINE,
    STATUS_NO_DRIFT,
    detect_drift,
    find_baseline_and_compare,
)
from app.models.analysis import STATUS_COMPLETE, Capture, SessionRecord

_SAFE_TLS = {"version_negotiated": "TLS 1.3", "cipher_suite_selected": "TLS_AES_256_GCM_SHA384", "forward_secrecy": True}
_SAFE_CERT = {"key_length_bits": 2048, "sha256_fingerprint": "a" * 64}
_SAFE_STARTTLS = {"status": "SUCCESS"}


def test_no_drift_when_nothing_changed():
    findings = detect_drift(_SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS, _SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS)
    assert findings == []


def test_tls_version_downgrade_detected():
    current_tls = {**_SAFE_TLS, "version_negotiated": "TLS 1.0"}
    findings = detect_drift(_SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS, current_tls, _SAFE_CERT, _SAFE_STARTTLS)
    titles = [f.title for f in findings]
    assert "TLS version downgraded since previous observation" in titles
    assert findings[titles.index("TLS version downgraded since previous observation")].severity == "HIGH"


def test_tls_version_upgrade_is_not_flagged():
    current_tls = {**_SAFE_TLS, "version_negotiated": "TLS 1.3"}
    baseline_tls = {**_SAFE_TLS, "version_negotiated": "TLS 1.2"}
    findings = detect_drift(baseline_tls, _SAFE_CERT, _SAFE_STARTTLS, current_tls, _SAFE_CERT, _SAFE_STARTTLS)
    assert findings == []


def test_forward_secrecy_loss_detected():
    current_tls = {**_SAFE_TLS, "forward_secrecy": False}
    findings = detect_drift(_SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS, current_tls, _SAFE_CERT, _SAFE_STARTTLS)
    titles = [f.title for f in findings]
    assert "Forward secrecy lost since previous observation" in titles


def test_certificate_key_length_decrease_detected():
    current_cert = {**_SAFE_CERT, "key_length_bits": 1024}
    findings = detect_drift(_SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS, _SAFE_TLS, current_cert, _SAFE_STARTTLS)
    titles = [f.title for f in findings]
    assert "Certificate key length decreased since previous observation" in titles


def test_certificate_rotation_reported_as_info():
    current_cert = {**_SAFE_CERT, "sha256_fingerprint": "b" * 64}
    findings = detect_drift(_SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS, _SAFE_TLS, current_cert, _SAFE_STARTTLS)
    rotation = next(f for f in findings if f.title == "Certificate rotated since previous observation")
    assert rotation.severity == "INFO"


def test_starttls_enforcement_regression_is_critical():
    current_starttls = {"status": "PLAINTEXT_AFTER_ADVERTISEMENT"}
    findings = detect_drift(_SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS, _SAFE_TLS, _SAFE_CERT, current_starttls)
    regression = next(f for f in findings if f.title == "STARTTLS enforcement regressed since previous observation")
    assert regression.severity == "CRITICAL"


def test_starttls_improvement_is_not_flagged():
    baseline_starttls = {"status": "NOT_USED"}
    current_starttls = {"status": "SUCCESS"}
    findings = detect_drift(_SAFE_TLS, _SAFE_CERT, baseline_starttls, _SAFE_TLS, _SAFE_CERT, current_starttls)
    assert findings == []


def test_missing_baseline_values_do_not_crash():
    findings = detect_drift({}, {}, {}, _SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS)
    assert findings == []


def _make_capture_with_session(db, server_ip, server_port, protocol, tls, cert, starttls):
    capture = Capture(filename=f"{server_ip}.pcap", status=STATUS_COMPLETE, completed_at=datetime.now(timezone.utc))
    db.add(capture)
    db.commit()
    db.refresh(capture)

    session = SessionRecord(
        capture_id=capture.id,
        session_id="SESS-SMTP-1",
        protocol=protocol,
        client_ip="192.168.1.1",
        client_port=52000,
        server_ip=server_ip,
        server_port=server_port,
        starttls=starttls,
        tls_handshake=tls,
        certificate=cert,
        findings=[],
        posture_score=100.0,
        risk_level="LOW",
        ai_analysis=None,
        crypto_fingerprint=None,
        drift=None,
    )
    db.add(session)
    db.commit()
    return capture, session


def test_find_baseline_and_compare_returns_no_baseline_for_first_observation():
    db = SessionLocal()
    try:
        capture, _ = _make_capture_with_session(
            db, "10.99.0.1", 25, "SMTP", _SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS
        )
        current_session_dict = {
            "server": {"ip": "10.99.0.1", "port": 25},
            "protocol": "SMTP",
            "tls_handshake": _SAFE_TLS,
            "certificate": _SAFE_CERT,
            "starttls_negotiation": _SAFE_STARTTLS,
        }
        result = find_baseline_and_compare(db, "some-other-capture-id-not-yet-persisted", current_session_dict)
        # capture itself is excluded only by its own id, so a *different* capture at the
        # same endpoint IS a valid baseline - assert against the id we actually created.
        result_same_capture = find_baseline_and_compare(db, capture.id, current_session_dict)
        assert result_same_capture["status"] == STATUS_NO_BASELINE
        assert result["status"] == STATUS_DRIFT_DETECTED or result["status"] == STATUS_NO_DRIFT
    finally:
        db.close()


def test_find_baseline_and_compare_detects_drift_across_captures():
    db = SessionLocal()
    try:
        weak_tls = {**_SAFE_TLS, "version_negotiated": "TLS 1.0"}
        baseline_capture, _ = _make_capture_with_session(
            db, "10.99.0.2", 25, "SMTP", _SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS
        )

        current_session_dict = {
            "server": {"ip": "10.99.0.2", "port": 25},
            "protocol": "SMTP",
            "tls_handshake": weak_tls,
            "certificate": _SAFE_CERT,
            "starttls_negotiation": _SAFE_STARTTLS,
        }
        result = find_baseline_and_compare(db, "yet-another-new-capture-id", current_session_dict)
        assert result["status"] == STATUS_DRIFT_DETECTED
        assert result["baseline_capture_id"] == baseline_capture.id
        titles = [f["title"] for f in result["findings"]]
        assert "TLS version downgraded since previous observation" in titles
    finally:
        db.close()


def test_find_baseline_and_compare_no_drift_when_configuration_unchanged():
    db = SessionLocal()
    try:
        _make_capture_with_session(db, "10.99.0.3", 25, "SMTP", _SAFE_TLS, _SAFE_CERT, _SAFE_STARTTLS)
        current_session_dict = {
            "server": {"ip": "10.99.0.3", "port": 25},
            "protocol": "SMTP",
            "tls_handshake": _SAFE_TLS,
            "certificate": _SAFE_CERT,
            "starttls_negotiation": _SAFE_STARTTLS,
        }
        result = find_baseline_and_compare(db, "brand-new-capture-id", current_session_dict)
        assert result["status"] == STATUS_NO_DRIFT
    finally:
        db.close()
