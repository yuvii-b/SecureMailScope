"""What-if remediation simulator (Stage 10, "strong" novelty item).

Answers "if I fixed X on this server, what would the posture score/findings become?"
without re-analyzing a new capture. Each catalog entry below is a pure patch function
operating on *copies* of the `tls_handshake`/`certificate`/`starttls` dicts already
stored for a session; `simulate_remediation()` applies the requested patches, reruns the
same deterministic `rules.engine.evaluate_session()` used for the real analysis, and
diffs the findings before/after. Never mutates the stored session and never contacts a
real mail server (CLAUDE.md §12) - this is purely "what would the deterministic rule
engine say about a hypothetically-patched configuration", nothing is sent over the wire.
"""
from __future__ import annotations

import copy

from ..rules.engine import evaluate_session


def _upgrade_tls_version(tls: dict, cert: dict, starttls: dict) -> None:
    tls["version_negotiated"] = "TLS 1.3"


def _remove_weak_cipher(tls: dict, cert: dict, starttls: dict) -> None:
    tls["cipher_suite_selected"] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    tls["key_exchange"] = "ECDHE"
    tls["forward_secrecy"] = True


def _enable_forward_secrecy(tls: dict, cert: dict, starttls: dict) -> None:
    tls["key_exchange"] = "ECDHE"
    tls["forward_secrecy"] = True


def _renew_certificate(tls: dict, cert: dict, starttls: dict) -> None:
    cert["expired"] = False
    cert["not_yet_valid"] = False


def _reissue_certificate_strong_key(tls: dict, cert: dict, starttls: dict) -> None:
    if cert.get("key_algorithm") == "RSA":
        cert["key_length_bits"] = 3072
    cert["signature_algorithm"] = "SHA256withRSA"


def _replace_self_signed_with_ca_issued(tls: dict, cert: dict, starttls: dict) -> None:
    cert["self_signed"] = False
    cert["chain_status"] = "OBSERVED_VALID"


def _enforce_starttls(tls: dict, cert: dict, starttls: dict) -> None:
    starttls["status"] = "SUCCESS"


REMEDIATION_CATALOG = {
    "upgrade_tls_version": {
        "title": "Upgrade to TLS 1.3",
        "description": "Reconfigure the server to negotiate TLS 1.3 instead of the observed version.",
        "domain": "protocol",
        "apply": _upgrade_tls_version,
    },
    "remove_weak_cipher": {
        "title": "Remove weak/critical cipher suites",
        "description": "Reconfigure the cipher preference list to offer only a modern AEAD, ECDHE cipher suite.",
        "domain": "cipher",
        "apply": _remove_weak_cipher,
    },
    "enable_forward_secrecy": {
        "title": "Enable forward secrecy (ECDHE/DHE)",
        "description": "Reconfigure key exchange to ECDHE so a later-compromised key cannot decrypt captured traffic.",
        "domain": "key_exchange",
        "apply": _enable_forward_secrecy,
    },
    "renew_certificate": {
        "title": "Renew the certificate",
        "description": "Replace an expired or not-yet-valid certificate with a currently valid one.",
        "domain": "certificate",
        "apply": _renew_certificate,
    },
    "reissue_certificate_strong_key": {
        "title": "Re-issue certificate with a strong key/signature",
        "description": "Replace the certificate's key with >= 3072-bit RSA and a SHA-256 signature.",
        "domain": "certificate",
        "apply": _reissue_certificate_strong_key,
    },
    "replace_self_signed_with_ca_issued": {
        "title": "Replace with a CA-issued certificate",
        "description": "Replace a self-signed/untrusted certificate with one issued by a trusted CA.",
        "domain": "certificate",
        "apply": _replace_self_signed_with_ca_issued,
    },
    "enforce_starttls": {
        "title": "Enforce mandatory STARTTLS",
        "description": "Reject plaintext continuation after an advertised STARTTLS upgrade instead of allowing it.",
        "domain": "starttls",
        "apply": _enforce_starttls,
    },
}


def list_remediations() -> list:
    return [
        {"id": rid, "title": r["title"], "description": r["description"], "domain": r["domain"]}
        for rid, r in REMEDIATION_CATALOG.items()
    ]


def simulate_remediation(tls_handshake: dict, certificate: dict, starttls: dict, remediation_ids: list) -> dict:
    unknown = [rid for rid in remediation_ids if rid not in REMEDIATION_CATALOG]
    if unknown:
        raise ValueError(f"Unknown remediation id(s): {', '.join(unknown)}")

    before = evaluate_session(tls_handshake or {}, certificate or {}, starttls or {})

    patched_tls = copy.deepcopy(tls_handshake or {})
    patched_cert = copy.deepcopy(certificate or {})
    patched_starttls = copy.deepcopy(starttls or {})
    for rid in remediation_ids:
        REMEDIATION_CATALOG[rid]["apply"](patched_tls, patched_cert, patched_starttls)

    after = evaluate_session(patched_tls, patched_cert, patched_starttls)

    before_titles = {f.title for f in before.findings}
    after_titles = {f.title for f in after.findings}

    return {
        "applied_remediations": remediation_ids,
        "before": before.to_dict(),
        "after": after.to_dict(),
        "posture_score_delta": round(after.posture_score - before.posture_score, 1),
        "findings_resolved": [f.to_dict() for f in before.findings if f.title not in after_titles],
        "findings_remaining": [f.to_dict() for f in after.findings if f.title in before_titles],
        "findings_newly_introduced": [f.to_dict() for f in after.findings if f.title not in before_titles],
    }
