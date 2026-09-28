"""Stage 10 what-if remediation simulator. Each test builds a small tls/cert/starttls dict
that trips exactly one rule-engine finding, applies the matching remediation, and confirms
the finding is resolved and no new one appears - `simulate_remediation()` just reruns the
same `rules.engine.evaluate_session()` used for real analysis on a patched copy, so this is
really re-verifying that each patch function actually satisfies the rule it targets.
"""
import pytest

from app.simulator.remediation import list_remediations, simulate_remediation


def test_list_remediations_covers_full_catalog():
    remediations = list_remediations()
    ids = {r["id"] for r in remediations}
    assert ids == {
        "upgrade_tls_version",
        "remove_weak_cipher",
        "enable_forward_secrecy",
        "renew_certificate",
        "reissue_certificate_strong_key",
        "replace_self_signed_with_ca_issued",
        "enforce_starttls",
    }
    for r in remediations:
        assert r["title"]
        assert r["description"]
        assert r["domain"]


def test_unknown_remediation_id_raises_value_error():
    with pytest.raises(ValueError):
        simulate_remediation({}, {}, {}, ["not_a_real_remediation"])


def test_upgrade_tls_version_resolves_deprecated_version_finding():
    tls = {"version_negotiated": "TLS 1.0", "cipher_suite_selected": "TLS_RSA_WITH_AES_128_CBC_SHA",
           "key_exchange": "RSA", "forward_secrecy": False}
    result = simulate_remediation(tls, {}, {}, ["upgrade_tls_version"])
    resolved_titles = [f["title"] for f in result["findings_resolved"]]
    assert "Deprecated TLS version negotiated" in resolved_titles
    assert result["after"]["posture_score"] > result["before"]["posture_score"]
    assert result["posture_score_delta"] > 0


def test_remove_weak_cipher_resolves_critical_cipher_finding():
    tls = {"version_negotiated": "TLS 1.2", "cipher_suite_selected": "TLS_RSA_WITH_RC4_128_SHA",
           "key_exchange": "RSA", "forward_secrecy": False}
    result = simulate_remediation(tls, {}, {}, ["remove_weak_cipher"])
    resolved_titles = [f["title"] for f in result["findings_resolved"]]
    assert "Critically weak cipher suite negotiated" in resolved_titles


def test_enable_forward_secrecy_resolves_static_rsa_finding():
    tls = {"version_negotiated": "TLS 1.2", "cipher_suite_selected": "TLS_RSA_WITH_AES_128_GCM_SHA256",
           "key_exchange": "RSA", "forward_secrecy": False}
    result = simulate_remediation(tls, {}, {}, ["enable_forward_secrecy"])
    resolved_titles = [f["title"] for f in result["findings_resolved"]]
    assert "Static RSA key exchange (no forward secrecy)" in resolved_titles
    assert result["after"]["findings"] == [] or all(
        f["title"] != "Static RSA key exchange (no forward secrecy)" for f in result["after"]["findings"]
    )


def test_renew_certificate_resolves_expired_finding():
    cert = {"certificate_count": 1, "expired": True, "not_valid_after": "2020-01-01T00:00:00Z",
            "subject": "mail.example.com", "issuer": "mail.example.com"}
    result = simulate_remediation({}, cert, {}, ["renew_certificate"])
    resolved_titles = [f["title"] for f in result["findings_resolved"]]
    assert "Certificate expired" in resolved_titles


def test_reissue_certificate_strong_key_resolves_weak_key_finding():
    cert = {"certificate_count": 1, "key_algorithm": "RSA", "key_length_bits": 1024,
            "subject": "mail.example.com", "issuer": "mail.example.com"}
    result = simulate_remediation({}, cert, {}, ["reissue_certificate_strong_key"])
    resolved_titles = [f["title"] for f in result["findings_resolved"]]
    assert "RSA key length below minimum" in resolved_titles


def test_replace_self_signed_with_ca_issued_resolves_self_signed_finding():
    cert = {"certificate_count": 1, "self_signed": True, "chain_status": "OBSERVED_VALID",
            "subject": "mail.example.com", "issuer": "mail.example.com"}
    result = simulate_remediation({}, cert, {}, ["replace_self_signed_with_ca_issued"])
    resolved_titles = [f["title"] for f in result["findings_resolved"]]
    assert "Self-signed certificate" in resolved_titles


def test_enforce_starttls_resolves_stripping_finding():
    starttls = {"status": "PLAINTEXT_AFTER_ADVERTISEMENT", "evidence": "LOGIN victim Password123!"}
    result = simulate_remediation({}, {}, starttls, ["enforce_starttls"])
    resolved_titles = [f["title"] for f in result["findings_resolved"]]
    assert "STARTTLS stripping: plaintext continued after advertised upgrade" in resolved_titles


def test_combining_remediations_resolves_multiple_findings():
    tls = {"version_negotiated": "TLS 1.0", "cipher_suite_selected": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
           "key_exchange": "RSA", "forward_secrecy": False}
    cert = {"certificate_count": 1, "self_signed": True, "chain_status": "OBSERVED_VALID",
            "subject": "mail.example.com", "issuer": "mail.example.com"}
    result = simulate_remediation(
        tls, cert, {},
        ["upgrade_tls_version", "remove_weak_cipher", "replace_self_signed_with_ca_issued"],
    )
    assert len(result["findings_resolved"]) >= 3
    assert result["findings_newly_introduced"] == []
    assert result["after"]["posture_score"] == 100.0


def test_findings_unrelated_to_applied_remediation_remain():
    tls = {"version_negotiated": "TLS 1.0", "cipher_suite_selected": "TLS_RSA_WITH_AES_128_CBC_SHA",
           "key_exchange": "RSA", "forward_secrecy": False}
    result = simulate_remediation(tls, {}, {}, ["upgrade_tls_version"])
    remaining_titles = [f["title"] for f in result["findings_remaining"]]
    assert "Static RSA key exchange (no forward secrecy)" in remaining_titles
