"""Feature extraction for the ML stage (Stage 9).

Turns the plain dicts/dataclasses Stages 3-5 already produce (the reassembled session,
its `tls_handshake`, `certificate` and `starttls` dicts) into the 19-feature vector named
in CLAUDE.md §7.1, ready for Isolation Forest anomaly detection and XGBoost risk
classification (both still to come in this stage).

Like the rule engine (Stage 6), this module only reads data Stages 3-5 already extracted -
it adds no new packet parsing of its own. Per CLAUDE.md §12, a feature that isn't
observable from the capture is reported as `None`, never guessed:

- `chain_valid` / `certificate_valid` are `None` when the certificate's issuing chain
  wasn't captured (`chain_status == "NOT_OBSERVABLE"`), not coerced to True or False.
- `handshake_duration` is always `None` for now: the TLS parser (`tls/records.py`,
  `tls/handshake.py`) works over concatenated per-direction byte streams with no
  per-record capture timestamps, so there is nothing to subtract yet. Computing this
  honestly would mean threading packet timestamps through the record parser - a Stage 4
  change, not a feature-extraction one. Revisit if a later scenario needs it.
- `handshake_failure_count` is a proxy (count of fatal-level TLS alerts observed), not a
  count of retried handshake attempts, since individual attempts aren't tracked either.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

# Exact order from CLAUDE.md §7.1.
FEATURE_NAMES = [
    "protocol",
    "tls_version",
    "cipher_suite",
    "key_exchange",
    "forward_secrecy",
    "certificate_valid",
    "certificate_age",
    "certificate_days_to_expiry",
    "public_key_algorithm",
    "public_key_length",
    "signature_algorithm",
    "chain_valid",
    "starttls_used",
    "handshake_success",
    "handshake_duration",
    "handshake_failure_count",
    "packet_count",
    "retransmission_count",
    "session_duration",
]

# Features that are structurally never observable yet (see module docstring) - kept
# separate from "not observable for this particular session" so callers/tests can tell
# the two apart.
ALWAYS_NONE_FEATURES = {"handshake_duration"}


def _parse_iso(timestamp: Optional[str]) -> Optional[datetime]:
    if not timestamp:
        return None
    return datetime.fromisoformat(timestamp)


def _certificate_validity_features(
    certificate: dict, capture_time: Optional[datetime]
) -> dict:
    if not certificate or not certificate.get("certificate_count"):
        return {
            "certificate_valid": None,
            "certificate_age": None,
            "certificate_days_to_expiry": None,
            "public_key_algorithm": None,
            "public_key_length": None,
            "signature_algorithm": None,
            "chain_valid": None,
        }

    chain_status = certificate.get("chain_status")
    chain_valid = {"OBSERVED_VALID": True, "INVALID": False}.get(chain_status)

    certificate_age = None
    certificate_days_to_expiry = None
    if capture_time is not None:
        not_before = _parse_iso(certificate.get("not_valid_before"))
        not_after = _parse_iso(certificate.get("not_valid_after"))
        if not_before is not None:
            certificate_age = (capture_time - not_before).days
        if not_after is not None:
            certificate_days_to_expiry = (not_after - capture_time).days

    certificate_valid = (
        chain_valid is True
        and not certificate.get("expired")
        and not certificate.get("not_yet_valid")
        if chain_valid is not None
        else None
    )

    return {
        "certificate_valid": certificate_valid,
        "certificate_age": certificate_age,
        "certificate_days_to_expiry": certificate_days_to_expiry,
        "public_key_algorithm": certificate.get("key_algorithm"),
        "public_key_length": certificate.get("key_length_bits"),
        "signature_algorithm": certificate.get("signature_algorithm"),
        "chain_valid": chain_valid,
    }


def _handshake_features(tls_handshake: dict) -> dict:
    tls_handshake = tls_handshake or {}
    handshake_success = bool(
        tls_handshake.get("client_hello_seen") and tls_handshake.get("server_hello_seen")
    ) and not any(a.get("level") == "fatal" for a in tls_handshake.get("alerts", []))
    handshake_failure_count = sum(
        1 for a in tls_handshake.get("alerts", []) if a.get("level") == "fatal"
    )
    return {
        "tls_version": tls_handshake.get("version_negotiated"),
        "cipher_suite": tls_handshake.get("cipher_suite_selected"),
        "key_exchange": tls_handshake.get("key_exchange"),
        "forward_secrecy": tls_handshake.get("forward_secrecy"),
        "handshake_success": handshake_success,
        "handshake_duration": None,
        "handshake_failure_count": handshake_failure_count,
    }


def extract_features(session, tls_handshake: dict, certificate: dict, starttls: dict) -> dict:
    """Builds the 19-feature dict for one reassembled session.

    `session` is a `reassembly.reassembler.ReassembledSession` (or anything exposing the
    same `protocol`/`capture_time`/`packet_count`/`duration_seconds`/`client_to_server`/
    `server_to_client` attributes); `tls_handshake`/`certificate`/`starttls` are the dicts
    Stages 4-5 and the STARTTLS state machine already produce for that same session.
    """
    capture_time = (
        datetime.fromtimestamp(session.capture_time, tz=timezone.utc)
        if session.capture_time is not None
        else None
    )

    features = {
        "protocol": session.protocol,
        "packet_count": session.packet_count,
        "retransmission_count": (
            session.client_to_server.retransmitted_segments
            + session.server_to_client.retransmitted_segments
        ),
        "session_duration": session.duration_seconds,
        "starttls_used": bool((starttls or {}).get("command_detected")),
    }
    features.update(_handshake_features(tls_handshake))
    features.update(_certificate_validity_features(certificate, capture_time))

    return {name: features[name] for name in FEATURE_NAMES}
