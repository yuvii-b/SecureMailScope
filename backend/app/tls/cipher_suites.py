"""Cipher-suite and TLS-version metadata lookup (Stage 4).

Mirrors the `CIPHERS` table in `genny.py` (the project's ground-truth fixture source, see
CLAUDE.md §5/§12) so parsed cipher IDs resolve to the same names/strengths the generator
used to build the synthetic dataset. Duplicated rather than imported: `genny.py` is a
standalone script outside the `backend` package, and the analyzer needs this table at
runtime independent of the generator.
"""
from __future__ import annotations

CIPHERS = {
    0x0000: {"name": "TLS_NULL_WITH_NULL_NULL", "key_exchange": "NULL", "strength": "critical"},
    0x0005: {"name": "TLS_RSA_WITH_RC4_128_SHA", "key_exchange": "RSA", "strength": "weak"},
    0x000A: {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "key_exchange": "RSA", "strength": "weak"},
    0x0018: {"name": "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "key_exchange": "DHE-ANON", "strength": "critical"},
    0x002F: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "key_exchange": "RSA", "strength": "legacy"},
    0x009E: {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "key_exchange": "DHE", "strength": "strong"},
    0xC02F: {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "key_exchange": "ECDHE", "strength": "strong"},
    0xC030: {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "key_exchange": "ECDHE", "strength": "strong"},
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "key_exchange": "TLS1.3", "strength": "strong"},
    0x1302: {"name": "TLS_AES_256_GCM_SHA384", "key_exchange": "TLS1.3", "strength": "strong"},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "key_exchange": "TLS1.3", "strength": "strong"},
}

_FORWARD_SECRET_KEY_EXCHANGES = {"ECDHE", "DHE", "DHE-ANON", "TLS1.3"}

_VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

_ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
}


def cipher_info(cipher_id: int) -> dict:
    return CIPHERS.get(
        cipher_id,
        {"name": f"UNKNOWN_0x{cipher_id:04x}", "key_exchange": "UNKNOWN", "strength": "unknown"},
    )


def has_forward_secrecy(key_exchange: str) -> bool:
    return key_exchange in _FORWARD_SECRET_KEY_EXCHANGES


def tls_version_name(version: int | None) -> str | None:
    if version is None:
        return None
    return _VERSION_NAMES.get(version, f"UNKNOWN_0x{version:04x}")


def alert_description_name(description: int) -> str:
    return _ALERT_DESCRIPTIONS.get(description, f"UNKNOWN_{description}")
