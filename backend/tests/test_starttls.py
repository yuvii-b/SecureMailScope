import pytest

from app.reassembly.reassembler import reassemble_pcap
from app.starttls.state_machine import (
    STATUS_IMPLICIT_TLS,
    STATUS_NOT_OBSERVED,
    STATUS_NOT_USED,
    STATUS_PLAINTEXT_AFTER_ADVERTISEMENT,
    STATUS_REJECTED,
    STATUS_SUCCESS,
    classify,
)


def _classify(dataset_dir, filename):
    sessions = reassemble_pcap(dataset_dir / filename)
    assert len(sessions) == 1
    session = sessions[0]
    result = classify(session.protocol, session.client_to_server.data, session.server_to_client.data)
    return session, result


def test_smtp_starttls_success(dataset_dir):
    session, result = _classify(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    assert session.protocol == "SMTP"
    assert result.status == STATUS_SUCCESS
    assert result.tls_client_stream is not None
    assert result.tls_client_stream[:1] == b"\x16"


def test_imap_starttls_not_used(dataset_dir):
    _, result = _classify(dataset_dir, "14_starttls_not_used.pcap")
    assert result.status == STATUS_NOT_USED


def test_imap_starttls_rejected(dataset_dir):
    _, result = _classify(dataset_dir, "14_starttls_rejected.pcap")
    assert result.status == STATUS_REJECTED
    assert "NO" in result.evidence


def test_imap_starttls_plaintext_after_advertisement(dataset_dir):
    _, result = _classify(dataset_dir, "14_starttls_plaintext_after_advertisement.pcap")
    assert result.status == STATUS_PLAINTEXT_AFTER_ADVERTISEMENT
    assert "LOGIN" in result.evidence


def test_pop3_no_starttls_attempted(dataset_dir):
    session, result = _classify(dataset_dir, "15_pop3_plaintext_credentials.pcap")
    assert session.protocol == "POP3"
    assert result.status == STATUS_NOT_OBSERVED


def test_implicit_tls_smtps(dataset_dir):
    _, result = _classify(dataset_dir, "07_tls13_safe.pcap")
    assert result.status == STATUS_IMPLICIT_TLS
    assert result.tls_client_stream[:1] == b"\x16"


def test_implicit_tls_like_on_nonstandard_port(dataset_dir):
    """File 19 has no SMTP/IMAP/POP3 banner at all (protocol UNKNOWN, see Stage 3), but
    is TLS from the very first byte - the same first-byte-0x16 signal that flags
    implicit TLS must fire here too, since STARTTLS simply doesn't apply."""
    session, result = _classify(dataset_dir, "19_malformed_tls.pcap")
    assert session.protocol == "UNKNOWN"
    assert result.status == STATUS_IMPLICIT_TLS


@pytest.mark.parametrize(
    "filename",
    [
        "01_tls10_3des_rsa.pcap",
        "02_tls11_rc4_rsa.pcap",
        "04_tls12_dhe_rsa.pcap",
        "05_tls12_null_cipher.pcap",
        "06_tls12_dh_anon_3des.pcap",
        "20_unexpected_tls_version.pcap",
    ],
)
def test_all_starttls_smtp_scenarios_succeed(dataset_dir, filename):
    _, result = _classify(dataset_dir, filename)
    assert result.status == STATUS_SUCCESS
