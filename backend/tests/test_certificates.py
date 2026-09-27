from datetime import datetime, timezone

import pytest

from app.certificates.analyzer import (
    CHAIN_INVALID,
    CHAIN_NOT_OBSERVABLE,
    CHAIN_OBSERVED_VALID,
    analyze_certificate_chain,
)
from app.reassembly.reassembler import reassemble_pcap
from app.starttls.state_machine import classify
from app.tls.handshake import analyze_tls_handshake


def _analyze(dataset_dir, filename):
    sessions = reassemble_pcap(dataset_dir / filename)
    session = sessions[0]
    starttls_result = classify(
        session.protocol, session.client_to_server.data, session.server_to_client.data
    )
    tls_info = analyze_tls_handshake(starttls_result.tls_client_stream, starttls_result.tls_server_stream)
    evaluation_time = datetime.fromtimestamp(session.capture_time, tz=timezone.utc)
    return analyze_certificate_chain(tls_info.certificates_der_hex, evaluation_time, tls_info.sni)


def test_valid_certificate_matches_hostname(dataset_dir):
    analysis = _analyze(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    assert analysis.certificate_count == 1
    assert analysis.leaf.subject == "mail.example.test"
    assert analysis.leaf.expired is False
    assert analysis.leaf.not_yet_valid is False
    assert analysis.leaf.hostname_match is True
    assert analysis.leaf.key_algorithm == "RSA"
    assert analysis.leaf.key_length_bits == 2048
    assert analysis.chain_status == CHAIN_OBSERVED_VALID


def test_expired_certificate_detected(dataset_dir):
    analysis = _analyze(dataset_dir, "08_cert_expired.pcap")
    assert analysis.leaf.expired is True
    assert analysis.leaf.not_yet_valid is False


def test_wrong_hostname_detected(dataset_dir):
    analysis = _analyze(dataset_dir, "09_cert_wrong_hostname.pcap")
    assert analysis.leaf.subject == "other.example.test"
    assert analysis.leaf.hostname_checked == "mail.example.test"
    assert analysis.leaf.hostname_match is False


def test_self_signed_certificate_detected(dataset_dir):
    analysis = _analyze(dataset_dir, "10_cert_self_signed.pcap")
    assert analysis.leaf.self_signed is True
    assert analysis.chain_status == CHAIN_OBSERVED_VALID


def test_weak_key_length_detected(dataset_dir):
    analysis = _analyze(dataset_dir, "11_cert_weak_key.pcap")
    assert analysis.leaf.key_algorithm == "RSA"
    assert analysis.leaf.key_length_bits == 1024


def test_weak_signature_algorithm_detected(dataset_dir):
    analysis = _analyze(dataset_dir, "12_cert_weak_signature_sha1.pcap")
    assert analysis.leaf.signature_algorithm == "SHA1withRSA"


def test_incomplete_chain_reported_not_observable(dataset_dir):
    analysis = _analyze(dataset_dir, "13_cert_incomplete_chain.pcap")
    assert analysis.certificate_count == 1
    assert analysis.leaf.self_signed is False
    assert analysis.chain_status == CHAIN_NOT_OBSERVABLE
    assert any("issuing CA certificate" in note for note in analysis.notes)


def test_no_certificate_observed_reports_not_observable(dataset_dir):
    analysis = _analyze(dataset_dir, "15_pop3_plaintext_credentials.pcap")
    assert analysis.certificate_count == 0
    assert analysis.leaf is None
    assert analysis.chain_status == CHAIN_NOT_OBSERVABLE


def test_fingerprint_is_stable_sha256_hex(dataset_dir):
    analysis = _analyze(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    assert len(analysis.leaf.sha256_fingerprint) == 64
    int(analysis.leaf.sha256_fingerprint, 16)  # raises if not valid hex


def test_mismatched_chain_reported_invalid(dataset_dir):
    """Two unrelated certificates stitched into one "chain" must fail verification,
    not be silently accepted - exercises the CHAIN_INVALID branch genny.py's dataset
    doesn't otherwise produce (every scenario is either a single leaf or a real chain).
    """
    leaf_hex = _analyze(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap").leaf
    other_hex = _analyze(dataset_dir, "10_cert_self_signed.pcap").leaf
    assert leaf_hex.subject != other_hex.subject

    sessions = reassemble_pcap(dataset_dir / "03_tls12_ecdhe_rsa_safe.pcap")
    session = sessions[0]
    starttls_result = classify(
        session.protocol, session.client_to_server.data, session.server_to_client.data
    )
    tls_info_a = analyze_tls_handshake(starttls_result.tls_client_stream, starttls_result.tls_server_stream)

    sessions_b = reassemble_pcap(dataset_dir / "10_cert_self_signed.pcap")
    session_b = sessions_b[0]
    starttls_result_b = classify(
        session_b.protocol, session_b.client_to_server.data, session_b.server_to_client.data
    )
    tls_info_b = analyze_tls_handshake(starttls_result_b.tls_client_stream, starttls_result_b.tls_server_stream)

    fake_chain = tls_info_a.certificates_der_hex + tls_info_b.certificates_der_hex
    analysis = analyze_certificate_chain(fake_chain, datetime.now(timezone.utc), hostname=None)
    assert analysis.certificate_count == 2
    assert analysis.chain_status == CHAIN_INVALID


@pytest.mark.parametrize(
    "filename",
    [
        "08_cert_expired.pcap",
        "09_cert_wrong_hostname.pcap",
        "10_cert_self_signed.pcap",
        "11_cert_weak_key.pcap",
        "12_cert_weak_signature_sha1.pcap",
    ],
)
def test_self_signed_leaf_scenarios_have_observed_valid_chain(dataset_dir, filename):
    analysis = _analyze(dataset_dir, filename)
    assert analysis.leaf.self_signed is True
    assert analysis.chain_status == CHAIN_OBSERVED_VALID
