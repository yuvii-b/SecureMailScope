"""Cryptographic config + certificate drift detection (Stage 10, "must-have" novelty item).

Compares a session's observed TLS/certificate/STARTTLS posture against the most recent
prior observation of the *same mail server* to flag configuration regressions that a
single-capture rule engine can never see - a downgrade only exists relative to a
baseline. The endpoint identity used for that match is `server_ip` + `server_port` +
`protocol`, not hostname/SNI, since SNI isn't always observed (CLAUDE.md §12) but the
network-layer endpoint always is.

Drift is deliberately a separate additive `drift` field alongside `findings`, never
merged into the rule engine's own `posture_score`/`risk_level` - mirrors CLAUDE.md §12's
"keep the rule engine and ML engine decoupled" convention: drift depends on cross-capture
history that may not exist yet (first-ever capture of an endpoint), so a single capture
must still be fully scoreable without it.

`detect_drift()` is a pure comparison of two already-computed dict triples - no DB
access, trivially unit-testable with hand-built dicts (the way `test_certificates.py`
hand-stitches a chain mismatch genny.py's dataset doesn't otherwise produce - no two
genny.py fixture files share a server endpoint, so a real before/after pair isn't
naturally available either). The one DB-touching function, `find_baseline_and_compare`,
is called from `worker.py`, the only place in the pipeline that already has both a
computed session dict and DB access (`api/pipeline.py` stays pure/DB-free per §12).
"""
from __future__ import annotations

from ..rules.engine import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_INFO, Finding

STATUS_NO_BASELINE = "NO_BASELINE"
STATUS_NO_DRIFT = "NO_DRIFT"
STATUS_DRIFT_DETECTED = "DRIFT_DETECTED"

# Higher rank = stronger. -1/-2 for SSL so a TLS-1.0-to-SSLv3 change is still a
# downgrade even though neither is in the "safe" range.
_TLS_VERSION_RANK = {
    "SSL 2.0": -2,
    "SSL 3.0": -1,
    "TLS 1.0": 0,
    "TLS 1.1": 1,
    "TLS 1.2": 2,
    "TLS 1.3": 3,
}

# Higher rank = stronger enforcement. PLAINTEXT_AFTER_ADVERTISEMENT/REJECTED and
# NOT_USED/NOT_OBSERVED are treated as equally weak/neutral tiers on purpose - the drift
# check only cares whether enforcement got strictly worse, not about ranking every status
# against every other (that's the rule engine's job for a single observation).
_STARTTLS_ENFORCEMENT_RANK = {
    "PLAINTEXT_AFTER_ADVERTISEMENT": 0,
    "REJECTED": 0,
    "NOT_USED": 1,
    "NOT_OBSERVED": 1,
    "SUCCESS": 2,
    "NOT_APPLICABLE_IMPLICIT_TLS": 2,
}


def detect_drift(
    baseline_tls: dict,
    baseline_cert: dict,
    baseline_starttls: dict,
    current_tls: dict,
    current_cert: dict,
    current_starttls: dict,
) -> list:
    baseline_tls = baseline_tls or {}
    current_tls = current_tls or {}
    baseline_cert = baseline_cert or {}
    current_cert = current_cert or {}
    baseline_starttls = baseline_starttls or {}
    current_starttls = current_starttls or {}

    findings: list[Finding] = []

    b_version = baseline_tls.get("version_negotiated")
    c_version = current_tls.get("version_negotiated")
    if b_version and c_version and b_version != c_version:
        b_rank = _TLS_VERSION_RANK.get(b_version)
        c_rank = _TLS_VERSION_RANK.get(c_version)
        if b_rank is not None and c_rank is not None and c_rank < b_rank:
            findings.append(Finding(
                severity=SEVERITY_HIGH,
                title="TLS version downgraded since previous observation",
                evidence=f"version_negotiated changed {b_version} -> {c_version}",
                policy_reference="RFC 8996",
                recommendation="Investigate why this endpoint now negotiates a weaker TLS "
                                "version than previously observed; this may indicate a "
                                "misconfiguration or a downgrade/interception attempt.",
                domain="drift",
                evidence_path="tls_handshake.version_negotiated",
            ))

    if baseline_tls.get("forward_secrecy") is True and current_tls.get("forward_secrecy") is False:
        findings.append(Finding(
            severity=SEVERITY_HIGH,
            title="Forward secrecy lost since previous observation",
            evidence="forward_secrecy changed True -> False "
                     f"(cipher_suite_selected={current_tls.get('cipher_suite_selected')})",
            policy_reference="NIST SP 800-52r2",
            recommendation="Restore ECDHE/DHE key exchange on this endpoint; a prior "
                            "observation showed forward secrecy was available.",
            domain="drift",
            evidence_path="tls_handshake.forward_secrecy",
        ))

    b_cipher = baseline_tls.get("cipher_suite_selected")
    c_cipher = current_tls.get("cipher_suite_selected")
    if b_cipher and c_cipher and b_cipher != c_cipher:
        findings.append(Finding(
            severity=SEVERITY_INFO,
            title="Negotiated cipher suite changed since previous observation",
            evidence=f"cipher_suite_selected changed {b_cipher} -> {c_cipher}",
            policy_reference="n/a",
            recommendation="Confirm this cipher suite change was an intentional "
                            "configuration update rather than an unexpected regression.",
            domain="drift",
            evidence_path="tls_handshake.cipher_suite_selected",
        ))

    b_len = baseline_cert.get("key_length_bits")
    c_len = current_cert.get("key_length_bits")
    if isinstance(b_len, int) and isinstance(c_len, int) and c_len < b_len:
        findings.append(Finding(
            severity=SEVERITY_HIGH,
            title="Certificate key length decreased since previous observation",
            evidence=f"key_length_bits changed {b_len} -> {c_len}",
            policy_reference="NIST SP 800-52r2",
            recommendation="Investigate why the newly observed certificate uses a shorter "
                            "key than the previous one seen for this endpoint.",
            domain="drift",
            evidence_path="certificate.key_length_bits",
        ))

    b_fp = baseline_cert.get("sha256_fingerprint")
    c_fp = current_cert.get("sha256_fingerprint")
    if b_fp and c_fp and b_fp != c_fp:
        findings.append(Finding(
            severity=SEVERITY_INFO,
            title="Certificate rotated since previous observation",
            evidence=f"sha256_fingerprint changed {b_fp[:16]}... -> {c_fp[:16]}...",
            policy_reference="RFC 5280",
            recommendation="Confirm this certificate rotation was planned (e.g. renewal); "
                            "an unexpected rotation may indicate compromise or a MITM.",
            domain="drift",
            evidence_path="certificate.sha256_fingerprint",
        ))

    b_starttls = baseline_starttls.get("status")
    c_starttls = current_starttls.get("status")
    if b_starttls and c_starttls and b_starttls != c_starttls:
        b_rank = _STARTTLS_ENFORCEMENT_RANK.get(b_starttls)
        c_rank = _STARTTLS_ENFORCEMENT_RANK.get(c_starttls)
        if b_rank is not None and c_rank is not None and c_rank < b_rank:
            findings.append(Finding(
                severity=SEVERITY_CRITICAL,
                title="STARTTLS enforcement regressed since previous observation",
                evidence=f"starttls status changed {b_starttls} -> {c_starttls}",
                policy_reference="RFC 3207, RFC 8314",
                recommendation="This endpoint previously enforced TLS more strictly; "
                                "investigate the regression immediately - it may indicate "
                                "stripping/interception or a broken configuration change.",
                domain="drift",
                evidence_path="starttls_negotiation.status",
            ))

    return findings


def find_baseline_and_compare(db, capture_id: str, session_dict: dict) -> dict:
    """Looks up the most recent prior session for the same endpoint and compares it.

    `db` is a SQLAlchemy `Session`; imports the models locally to avoid a circular import
    (models -> db; this module is imported by `worker.py`, which already imports models).
    """
    from ..models.analysis import STATUS_COMPLETE, Capture, SessionRecord

    server = session_dict["server"]
    baseline = (
        db.query(SessionRecord)
        .join(Capture, SessionRecord.capture_id == Capture.id)
        .filter(
            SessionRecord.server_ip == server["ip"],
            SessionRecord.server_port == server["port"],
            SessionRecord.protocol == session_dict["protocol"],
            SessionRecord.capture_id != capture_id,
            Capture.status == STATUS_COMPLETE,
        )
        .order_by(Capture.completed_at.desc())
        .first()
    )
    if baseline is None:
        return {
            "status": STATUS_NO_BASELINE,
            "baseline_capture_id": None,
            "baseline_session_id": None,
            "findings": [],
        }

    findings = detect_drift(
        baseline.tls_handshake, baseline.certificate, baseline.starttls,
        session_dict["tls_handshake"], session_dict["certificate"], session_dict["starttls_negotiation"],
    )
    return {
        "status": STATUS_DRIFT_DETECTED if findings else STATUS_NO_DRIFT,
        "baseline_capture_id": baseline.capture_id,
        "baseline_session_id": baseline.session_id,
        "findings": [f.to_dict() for f in findings],
    }
