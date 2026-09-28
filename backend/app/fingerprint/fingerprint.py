"""Cryptographic fingerprinting (Stage 10, "strong" novelty item).

Combines the observable cryptographic configuration of a session - negotiated TLS
version, key exchange, cipher suite, certificate key algorithm/length, and certificate
SHA-256 fingerprint - into one short, comparable ID. Two sessions hitting the same mail
server produce the same `fingerprint_id` if and only if their cryptographic posture is
identical; any change (a cipher swap, a certificate rotation, a TLS downgrade) changes
the ID. `drift/detector.py` uses this as an O(1) "did anything change at all" check
before running its more detailed field-by-field comparison.

Pure function of the `tls_handshake`/`certificate` dicts Stages 4-5 already produce - no
new packet parsing, no DB access. Mirrors CLAUDE.md §12's "never guess an unobservable
value" convention via the `observable` flag: a session with no negotiated TLS version
(handshake never completed, or wasn't captured) gets `observable: False` and a `None`
fingerprint_id rather than a fingerprint hashed from absent evidence.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional


@dataclass
class CryptoFingerprint:
    observable: bool
    fingerprint_id: Optional[str]
    components: dict

    def to_dict(self) -> dict:
        return {
            "observable": self.observable,
            "fingerprint_id": self.fingerprint_id,
            "components": self.components,
        }


def compute_fingerprint(tls_handshake: dict, certificate: dict) -> CryptoFingerprint:
    tls_handshake = tls_handshake or {}
    certificate = certificate or {}

    components = {
        "tls_version": tls_handshake.get("version_negotiated"),
        "key_exchange": tls_handshake.get("key_exchange"),
        "cipher_suite": tls_handshake.get("cipher_suite_selected"),
        "certificate_key_algorithm": certificate.get("key_algorithm"),
        "certificate_key_length_bits": certificate.get("key_length_bits"),
        "certificate_sha256": certificate.get("sha256_fingerprint"),
    }

    if components["tls_version"] is None:
        # No completed handshake observed - there is nothing cryptographic to fingerprint.
        return CryptoFingerprint(observable=False, fingerprint_id=None, components=components)

    canonical = "|".join(f"{key}={value}" for key, value in sorted(components.items()))
    fingerprint_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return CryptoFingerprint(observable=True, fingerprint_id=fingerprint_id, components=components)
