from app.api.pipeline import analyze_session
from app.ml.features import ALWAYS_NONE_FEATURES, FEATURE_NAMES, extract_features
from app.reassembly.reassembler import reassemble_pcap


def _features_for(dataset_dir, filename, index=0):
    sessions = reassemble_pcap(dataset_dir / filename)
    session = sessions[index]
    analysis = analyze_session(session)
    features = extract_features(
        session, analysis["tls_handshake"], analysis["certificate"], analysis["starttls"]
    )
    return features


def test_feature_dict_has_exactly_the_19_named_features(dataset_dir):
    features = _features_for(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    assert list(features.keys()) == FEATURE_NAMES
    assert len(FEATURE_NAMES) == 19


def test_weak_tls10_3des_static_rsa_session(dataset_dir):
    features = _features_for(dataset_dir, "01_tls10_3des_rsa.pcap")

    assert features["protocol"] == "SMTP"
    assert features["tls_version"] == "TLS 1.0"
    assert "3DES" in features["cipher_suite"]
    assert features["key_exchange"] == "RSA"
    assert features["forward_secrecy"] is False
    assert features["handshake_success"] is True
    assert features["starttls_used"] is True
    assert features["public_key_algorithm"] == "RSA"
    assert features["chain_valid"] is True  # genny.py's leaf certs are self-signed-but-verifying
    assert features["certificate_valid"] is True
    assert features["packet_count"] > 0
    assert features["session_duration"] is not None and features["session_duration"] >= 0
    assert features["retransmission_count"] == 0


def test_safe_ecdhe_session_has_forward_secrecy(dataset_dir):
    features = _features_for(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")

    assert features["tls_version"] == "TLS 1.2"
    assert features["key_exchange"] == "ECDHE"
    assert features["forward_secrecy"] is True
    assert features["handshake_success"] is True


def test_implicit_tls13_session_has_no_starttls_command(dataset_dir):
    features = _features_for(dataset_dir, "07_tls13_safe.pcap")

    assert features["tls_version"] == "TLS 1.3"
    # TLS is implicit from the first byte here - there is genuinely no STARTTLS command
    # to observe, not an unknown value.
    assert features["starttls_used"] is False


def test_expired_certificate_is_invalid_despite_self_signed_chain_verifying(dataset_dir):
    features = _features_for(dataset_dir, "08_cert_expired.pcap")

    assert features["chain_valid"] is True
    assert features["certificate_valid"] is False
    assert features["certificate_days_to_expiry"] is not None
    assert features["certificate_days_to_expiry"] < 0


def test_incomplete_chain_reports_not_observable_not_a_guess(dataset_dir):
    features = _features_for(dataset_dir, "13_cert_incomplete_chain.pcap")

    assert features["chain_valid"] is None
    assert features["certificate_valid"] is None


def test_pop3_plaintext_session_has_no_tls_evidence(dataset_dir):
    features = _features_for(dataset_dir, "15_pop3_plaintext_credentials.pcap")

    assert features["protocol"] == "POP3"
    assert features["tls_version"] is None
    assert features["cipher_suite"] is None
    assert features["handshake_success"] is False
    assert features["starttls_used"] is False
    assert features["public_key_algorithm"] is None


def test_malformed_handshake_is_not_reported_as_success(dataset_dir):
    features = _features_for(dataset_dir, "19_malformed_tls.pcap")

    assert features["handshake_success"] is False
    assert features["handshake_failure_count"] >= 1


def test_handshake_duration_is_always_none_for_now(dataset_dir):
    # Documented gap (see ml/features.py docstring): not observable with the current
    # timestamp-free TLS record parser. Asserted explicitly so this test starts failing
    # - as a reminder to update it - the day that parser gains per-record timestamps.
    features = _features_for(dataset_dir, "03_tls12_ecdhe_rsa_safe.pcap")
    assert features["handshake_duration"] is None
    assert ALWAYS_NONE_FEATURES == {"handshake_duration"}


def test_multi_session_file_yields_features_for_each_session(dataset_dir):
    sessions = reassemble_pcap(dataset_dir / "22_multiple_sessions_combined.pcap")
    assert len(sessions) == 3

    for session in sessions:
        analysis = analyze_session(session)
        features = extract_features(
            session, analysis["tls_handshake"], analysis["certificate"], analysis["starttls"]
        )
        assert features["packet_count"] > 0
        assert features["session_duration"] is not None
