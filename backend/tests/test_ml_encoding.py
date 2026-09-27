from app.ml.encoding import FeatureEncoder

_BASE_FEATURES = {
    "protocol": "SMTP",
    "tls_version": "TLS 1.2",
    "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "key_exchange": "ECDHE",
    "forward_secrecy": True,
    "certificate_valid": True,
    "certificate_age": 10,
    "certificate_days_to_expiry": 300,
    "public_key_algorithm": "RSA",
    "public_key_length": 2048,
    "signature_algorithm": "SHA256withRSA",
    "chain_valid": True,
    "starttls_used": True,
    "handshake_success": True,
    "handshake_duration": None,
    "handshake_failure_count": 0,
    "packet_count": 20,
    "retransmission_count": 0,
    "session_duration": 1.5,
}


def _features(**overrides) -> dict:
    return {**_BASE_FEATURES, **overrides}


def test_fit_transform_produces_one_row_per_input_with_fixed_columns():
    encoder = FeatureEncoder()
    rows = encoder.fit_transform([_features(), _features(protocol="POP3")])

    assert len(rows) == 2
    assert list(rows.columns) == encoder.columns
    assert "protocol=SMTP" in rows.columns
    assert "protocol=POP3" in rows.columns


def test_unseen_category_at_transform_time_goes_to_the_unseen_bucket():
    encoder = FeatureEncoder().fit([_features(protocol="SMTP")])
    row = encoder.transform([_features(protocol="IMAP")])

    assert row.loc[0, "protocol=SMTP"] == 0.0
    assert row.loc[0, "protocol=__unseen__"] == 1.0


def test_a_literal_unknown_category_value_does_not_collide_with_the_unseen_bucket():
    # protocol_id.py itself reports "UNKNOWN" for unidentifiable traffic (files 19/21) -
    # that must not collide with the encoder's own catch-all column for values it has
    # never seen at all.
    encoder = FeatureEncoder().fit([_features(protocol="UNKNOWN"), _features(protocol="SMTP")])
    assert len(encoder.columns) == len(set(encoder.columns))

    row = encoder.transform([_features(protocol="UNKNOWN")])
    assert row.loc[0, "protocol=UNKNOWN"] == 1.0
    assert row.loc[0, "protocol=__unseen__"] == 0.0


def test_none_value_sets_observed_flag_to_zero_without_guessing_a_default():
    encoder = FeatureEncoder().fit([_features(), _features(certificate_valid=None, certificate_age=None)])
    row = encoder.transform([_features(certificate_valid=None, certificate_age=None)])

    assert row.loc[0, "certificate_valid"] == 0.0
    assert row.loc[0, "certificate_valid_observed"] == 0.0
    assert row.loc[0, "certificate_age"] == 0.0
    assert row.loc[0, "certificate_age_observed"] == 0.0


def test_observed_false_boolean_is_distinguished_from_not_observed():
    encoder = FeatureEncoder().fit([_features(forward_secrecy=False), _features(forward_secrecy=None)])

    observed_false = encoder.transform([_features(forward_secrecy=False)])
    not_observed = encoder.transform([_features(forward_secrecy=None)])

    assert observed_false.loc[0, "forward_secrecy"] == 0.0
    assert observed_false.loc[0, "forward_secrecy_observed"] == 1.0
    assert not_observed.loc[0, "forward_secrecy"] == 0.0
    assert not_observed.loc[0, "forward_secrecy_observed"] == 0.0
