from datetime import datetime, timezone

from app.certificates.analyzer import analyze_certificate_chain
from app.reassembly.reassembler import reassemble_pcap
from app.rules.engine import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    evaluate_session,
)
from app.starttls.state_machine import classify
from app.tls.handshake import analyze_tls_handshake


def _evaluate(dataset_dir, filename):
    sessions = reassemble_pcap(dataset_dir / filename)
    session = sessions[0]
    starttls_result = classify(
        session.protocol, session.client_to_server.data, session.server_to_client.data
    )
    tls_info = analyze_tls_handshake(starttls_result.tls_client_stream, starttls_result.tls_server_stream)
    evaluation_time = (
        datetime.fromtimestamp(session.capture_time, tz=timezone.utc)
        if session.capture_time is not None
        else None
    )
    certificate_analysis = analyze_certificate_chain(
        tls_info.certificates_der_hex, evaluation_time=evaluation_time, hostname=tls_info.sni
    )
    return evaluate_session(tls_info.to_dict(), certificate_analysis.to_dict(), starttls_result.to_dict())


def _titles(result):
    return {f.title for f in result.findings}


def test_deprecated_tls10_weak_cipher_and_static_rsa_all_flagged(dataset_dir):
    result = _evaluate(dataset_dir, "01_tls10_3des_rsa.pcap")
    titles = _titles(result)
    assert "Deprecated TLS version negotiated" in titles
    assert "Critically weak cipher suite negotiated" in titles
    assert "Static RSA key exchange (no forward secrecy)" in titles
    severities = {f.severity for f in result.findings}
    assert SEVERITY_CRITICAL in severities
    assert SEVERITY_HIGH in severities
    assert result.risk_level == "CRITICAL"


def test_deprecated_tls11_and_rc4_flagged(dataset_dir):
    result = _evaluate(dataset_dir, "02_tls11_rc4_rsa.pcap")
    assert "Deprecated TLS version negotiated" in _titles(result)
    critical = [f for f in result.findings if f.title == "Critically weak cipher suite negotiated"]
    assert critical and "RC4" in critical[0].evidence


def test_null_cipher_flagged_critical(dataset_dir):
    result = _evaluate(dataset_dir, "05_tls12_null_cipher.pcap")
    critical = [f for f in result.findings if f.title == "Critically weak cipher suite negotiated"]
    assert critical and "NULL" in critical[0].evidence


def test_dh_anon_cipher_flagged_critical(dataset_dir):
    result = _evaluate(dataset_dir, "06_tls12_dh_anon_3des.pcap")
    critical = [f for f in result.findings if f.title == "Critically weak cipher suite negotiated"]
    assert critical
    assert "ANON" in critical[0].evidence and "3DES" in critical[0].evidence


def test_safe_tls12_ecdhe_has_no_protocol_cipher_or_key_exchange_findings(dataset_dir):
    result = _evaluate(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    domains = {f.domain for f in result.findings}
    assert "protocol" not in domains
    assert "cipher" not in domains
    assert "key_exchange" not in domains


def test_tls13_safe_has_no_protocol_cipher_or_key_exchange_findings(dataset_dir):
    result = _evaluate(dataset_dir, "07_tls13_safe.pcap")
    domains = {f.domain for f in result.findings}
    assert "protocol" not in domains
    assert "cipher" not in domains
    assert "key_exchange" not in domains


def test_expired_certificate_flagged_high(dataset_dir):
    result = _evaluate(dataset_dir, "08_cert_expired.pcap")
    matches = [f for f in result.findings if f.title == "Certificate expired"]
    assert matches and matches[0].severity == SEVERITY_HIGH


def test_self_signed_certificate_flagged_high(dataset_dir):
    result = _evaluate(dataset_dir, "10_cert_self_signed.pcap")
    matches = [f for f in result.findings if f.title == "Self-signed certificate"]
    assert matches and matches[0].severity == SEVERITY_HIGH


def test_weak_key_length_flagged_high(dataset_dir):
    result = _evaluate(dataset_dir, "11_cert_weak_key.pcap")
    matches = [f for f in result.findings if f.title == "RSA key length below minimum"]
    assert matches and matches[0].severity == SEVERITY_HIGH


def test_weak_signature_algorithm_flagged_high(dataset_dir):
    result = _evaluate(dataset_dir, "12_cert_weak_signature_sha1.pcap")
    matches = [f for f in result.findings if f.title == "Weak certificate signature algorithm"]
    assert matches and matches[0].severity == SEVERITY_HIGH


def test_incomplete_chain_is_informational_not_a_trust_finding(dataset_dir):
    """A chain that's merely NOT_OBSERVABLE (file 13's leaf-only capture) isn't proof of
    anything untrustworthy - it should surface as INFO evidence, not an INVALID/self-signed
    HIGH finding (see the CHAIN_NOT_OBSERVABLE vs CHAIN_INVALID distinction in
    app/certificates/analyzer.py).
    """
    result = _evaluate(dataset_dir, "13_cert_incomplete_chain.pcap")
    info_matches = [f for f in result.findings if f.title == "Certificate chain not fully observable"]
    assert info_matches and info_matches[0].severity == SEVERITY_INFO
    assert not any(f.title == "Certificate chain does not cryptographically verify" for f in result.findings)
    assert not any(f.title == "Self-signed certificate" for f in result.findings)


def test_starttls_plaintext_after_advertisement_is_critical(dataset_dir):
    result = _evaluate(dataset_dir, "14_starttls_plaintext_after_advertisement.pcap")
    matches = [f for f in result.findings if f.domain == "starttls"]
    assert matches and matches[0].severity == SEVERITY_CRITICAL
    assert result.risk_level == "CRITICAL"


def test_starttls_success_produces_no_starttls_finding(dataset_dir):
    result = _evaluate(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    assert not any(f.domain == "starttls" for f in result.findings)


def test_findings_sorted_most_severe_first(dataset_dir):
    result = _evaluate(dataset_dir, "01_tls10_3des_rsa.pcap")
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [rank[f.severity] for f in result.findings]
    assert ranks == sorted(ranks)


def test_cbc_mode_on_tls12_flagged_medium():
    """genny.py's dataset never negotiates a CBC-mode cipher at TLS 1.2 (only the safe
    GCM/ChaCha20 suites and the deliberately-critical NULL/3DES/anon ones), so this rule
    is exercised directly against a synthetic handshake dict instead.
    """
    tls = {
        "version_negotiated": "TLS 1.2",
        "cipher_suite_selected": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "key_exchange": "RSA",
        "forward_secrecy": False,
    }
    result = evaluate_session(tls, {}, {})
    cbc_matches = [f for f in result.findings if f.title == "CBC-mode cipher suite negotiated on TLS 1.2"]
    assert cbc_matches and cbc_matches[0].severity == "MEDIUM"
    # the static-RSA/no-PFS finding should also fire independently
    assert any(f.title == "Static RSA key exchange (no forward secrecy)" for f in result.findings)


def test_posture_score_and_risk_level_for_clean_session():
    result = evaluate_session({}, {}, {})
    assert result.findings == []
    assert result.posture_score == 100.0
    assert result.risk_level == "LOW"


def test_posture_score_floors_at_zero_with_many_critical_findings():
    tls = {
        "version_negotiated": "SSL 3.0",
        "cipher_suite_selected": "TLS_NULL_WITH_NULL_NULL",
        "key_exchange": "NULL",
        "forward_secrecy": None,
    }
    starttls = {"status": "PLAINTEXT_AFTER_ADVERTISEMENT", "evidence": "plaintext continued"}
    result = evaluate_session(tls, {}, starttls)
    assert result.posture_score == 0.0
    assert result.risk_level == "CRITICAL"
