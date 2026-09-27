import pytest

from app.reassembly.reassembler import reassemble_pcap
from app.starttls.state_machine import classify
from app.tls.handshake import analyze_tls_handshake


def _analyze(dataset_dir, filename):
    sessions = reassemble_pcap(dataset_dir / filename)
    session = sessions[0]
    starttls_result = classify(
        session.protocol, session.client_to_server.data, session.server_to_client.data
    )
    return analyze_tls_handshake(starttls_result.tls_client_stream, starttls_result.tls_server_stream)


@pytest.mark.parametrize(
    "filename,version,cipher_name,key_exchange,forward_secrecy",
    [
        ("01_tls10_3des_rsa.pcap", "TLS 1.0", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", False),
        ("02_tls11_rc4_rsa.pcap", "TLS 1.1", "TLS_RSA_WITH_RC4_128_SHA", "RSA", False),
        ("03_tls12_ecdhe_rsa_safe.pcap", "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", True),
        ("04_tls12_dhe_rsa.pcap", "TLS 1.2", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", True),
        ("05_tls12_null_cipher.pcap", "TLS 1.2", "TLS_NULL_WITH_NULL_NULL", "NULL", False),
        ("06_tls12_dh_anon_3des.pcap", "TLS 1.2", "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "DHE-ANON", True),
    ],
)
def test_version_and_cipher_matrix(dataset_dir, filename, version, cipher_name, key_exchange, forward_secrecy):
    info = _analyze(dataset_dir, filename)
    assert info.client_hello_seen
    assert info.server_hello_seen
    assert info.version_negotiated == version
    assert info.cipher_suite_selected == cipher_name
    assert info.key_exchange == key_exchange
    assert info.forward_secrecy is forward_secrecy


def test_tls13_implicit_handshake_with_certificate_and_sni(dataset_dir):
    info = _analyze(dataset_dir, "07_tls13_safe.pcap")
    assert info.version_negotiated == "TLS 1.3"
    assert info.cipher_suite_selected == "TLS_AES_128_GCM_SHA256"
    assert info.key_exchange == "TLS1.3"
    assert info.forward_secrecy is True
    assert info.sni == "mail.example.test"
    assert len(info.certificates_der_hex) == 1


@pytest.mark.parametrize(
    "filename",
    [
        "08_cert_expired.pcap",
        "09_cert_wrong_hostname.pcap",
        "10_cert_self_signed.pcap",
        "11_cert_weak_key.pcap",
        "12_cert_weak_signature_sha1.pcap",
        "13_cert_incomplete_chain.pcap",
    ],
)
def test_certificate_scenarios_extract_der(dataset_dir, filename):
    info = _analyze(dataset_dir, filename)
    assert info.server_hello_seen
    assert len(info.certificates_der_hex) == 1


def test_unexpected_tls_version_reported_without_guessing(dataset_dir):
    info = _analyze(dataset_dir, "20_unexpected_tls_version.pcap")
    assert info.server_hello_seen
    assert info.version_negotiated == "UNKNOWN_0x0399"
    assert info.cipher_suite_selected == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"


def test_unusual_cipher_reported_as_unknown(dataset_dir):
    info = _analyze(dataset_dir, "21_unusual_cipher.pcap")
    assert info.server_hello_seen
    assert info.cipher_suite_selected == "UNKNOWN_0xfefe"
    assert info.key_exchange == "UNKNOWN"
    assert info.forward_secrecy is False


def test_malformed_handshake_does_not_crash_and_is_reported(dataset_dir):
    info = _analyze(dataset_dir, "19_malformed_tls.pcap")
    assert info.client_hello_seen is False
    assert info.server_hello_seen is False
    assert any("ClientHello" in note for note in info.notes)
    assert any("ServerHello" in note for note in info.notes)
    assert any(a["description"] == "handshake_failure" for a in info.alerts)


def test_no_tls_bytes_reports_not_observed(dataset_dir):
    info = _analyze(dataset_dir, "15_pop3_plaintext_credentials.pcap")
    assert info.handshake_observed is False
    assert info.notes == ["no TLS bytes observed for this session"]
