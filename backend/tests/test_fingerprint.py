from app.certificates.analyzer import analyze_certificate_chain
from app.fingerprint.fingerprint import compute_fingerprint
from app.reassembly.reassembler import reassemble_pcap
from app.starttls.state_machine import classify
from app.tls.handshake import analyze_tls_handshake


def _dicts(dataset_dir, filename):
    session = reassemble_pcap(dataset_dir / filename)[0]
    starttls_result = classify(
        session.protocol, session.client_to_server.data, session.server_to_client.data
    )
    tls_info = analyze_tls_handshake(starttls_result.tls_client_stream, starttls_result.tls_server_stream)
    certificate = analyze_certificate_chain(tls_info.certificates_der_hex, hostname=tls_info.sni)
    return tls_info.to_dict(), certificate.to_dict()


def test_fingerprint_observable_for_completed_handshake(dataset_dir):
    tls_dict, cert_dict = _dicts(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    fp = compute_fingerprint(tls_dict, cert_dict)
    assert fp.observable is True
    assert fp.fingerprint_id is not None
    assert len(fp.fingerprint_id) == 16
    int(fp.fingerprint_id, 16)  # raises if not valid hex


def test_fingerprint_not_observable_without_handshake():
    fp = compute_fingerprint({}, {})
    assert fp.observable is False
    assert fp.fingerprint_id is None


def test_fingerprint_is_deterministic(dataset_dir):
    tls_dict, cert_dict = _dicts(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    first = compute_fingerprint(tls_dict, cert_dict)
    second = compute_fingerprint(tls_dict, cert_dict)
    assert first.fingerprint_id == second.fingerprint_id


def test_fingerprint_differs_for_different_configurations(dataset_dir):
    weak_tls, weak_cert = _dicts(dataset_dir, "01_tls10_3des_rsa.pcap")
    safe_tls, safe_cert = _dicts(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    weak_fp = compute_fingerprint(weak_tls, weak_cert)
    safe_fp = compute_fingerprint(safe_tls, safe_cert)
    assert weak_fp.fingerprint_id != safe_fp.fingerprint_id


def test_fingerprint_changes_when_only_certificate_changes(dataset_dir):
    tls_dict, cert_dict_a = _dicts(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    _, cert_dict_b = _dicts(dataset_dir, "10_cert_self_signed.pcap")
    fp_a = compute_fingerprint(tls_dict, cert_dict_a)
    fp_b = compute_fingerprint(tls_dict, cert_dict_b)
    assert fp_a.fingerprint_id != fp_b.fingerprint_id
