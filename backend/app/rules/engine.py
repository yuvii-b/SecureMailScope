"""Deterministic security rule engine (Stage 6).

Turns the evidence Stages 3-5 already extracted (STARTTLS outcome, TLS handshake
fields, certificate analysis) into findings, per the reference matrix in CLAUDE.md §8.
Every finding carries the literal evidence value observed, the policy it violates, and a
plain-language recommendation - never a bare score (the docs explicitly warn against
"over-scoring", a single arbitrary number with no drill-down). Severity weights and risk
bands are config at the top of this module, not magic numbers buried in check logic, so
they can be tuned without touching detection rules.

This module only reads the plain dicts Stage 3-5 already produce (`tls_handshake`,
`certificate`, `starttls`) - it has no dependency on the ML engine (Stage 9) and must
keep working standalone if that stage is disabled or under-trained (CLAUDE.md §12).

One matrix entry is deliberately not implemented: "DH group below configured minimum".
Stage 4's TLS parser only extracts the cipher suite name from ServerHello, not the actual
DH parameters from ServerKeyExchange, so the group size isn't observable yet - guessing it
would violate CLAUDE.md §12's "report not observable, never assume" rule.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Configurable, not hardcoded inline: how much each severity subtracts from a session's
# posture score (100 = perfect). Tune these without touching any check function below.
SEVERITY_WEIGHTS = {
    SEVERITY_CRITICAL: 40,
    SEVERITY_HIGH: 25,
    SEVERITY_MEDIUM: 10,
    SEVERITY_LOW: 5,
    SEVERITY_INFO: 0,
}

# Ordered highest-score-first; the first band whose threshold the score meets applies.
RISK_LEVEL_BANDS = [
    (90, "LOW"),
    (70, "MEDIUM"),
    (40, "HIGH"),
    (0, "CRITICAL"),
]

# A single finding of a given severity guarantees at least this overall risk level, even
# if the arithmetic score alone would land in a lower band (e.g. one CRITICAL finding on
# an otherwise-clean session should never be reported as merely "HIGH" risk).
_SEVERITY_RISK_FLOOR = {
    SEVERITY_CRITICAL: "CRITICAL",
    SEVERITY_HIGH: "HIGH",
    SEVERITY_MEDIUM: "MEDIUM",
}
_RISK_LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_DEPRECATED_TLS_VERSION_POLICY = {
    "TLS 1.0": "RFC 8996",
    "TLS 1.1": "RFC 8996",
}
_INSECURE_SSL_VERSION_POLICY = {
    "SSL 3.0": "RFC 7568",
    "SSL 2.0": "RFC 6176",
}

# Matched case-insensitively against the negotiated cipher suite name.
_CRITICAL_CIPHER_PATTERNS = ("NULL", "ANON", "RC4", "3DES", "EXPORT")

_MIN_RSA_KEY_LENGTH_BITS = 2048


@dataclass
class Finding:
    severity: str
    title: str
    evidence: str
    policy_reference: str
    recommendation: str
    domain: str
    # Stage 10: JSON-pointer-style path into the session contract (§7) that this finding
    # was derived from - e.g. "tls_handshake.version_negotiated" - so a UI can link a
    # finding straight to the evidence field/session/handshake value it came from
    # (CLAUDE.md §10's "evidence-linked findings" item) rather than only a prose string.
    evidence_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence,
            "policy_reference": self.policy_reference,
            "recommendation": self.recommendation,
            "domain": self.domain,
            "evidence_path": self.evidence_path,
        }


@dataclass
class RuleEngineResult:
    findings: list = field(default_factory=list)
    posture_score: float = 100.0
    risk_level: str = "LOW"

    def to_dict(self) -> dict:
        return {
            "posture_score": self.posture_score,
            "risk_level": self.risk_level,
            "findings": [f.to_dict() for f in self.findings],
        }


def _check_protocol_version(tls: dict) -> list[Finding]:
    version = tls.get("version_negotiated")
    if version is None:
        return []

    if version in _INSECURE_SSL_VERSION_POLICY:
        return [Finding(
            severity=SEVERITY_CRITICAL,
            title="Insecure SSL protocol version negotiated",
            evidence=f"version_negotiated={version}",
            policy_reference=_INSECURE_SSL_VERSION_POLICY[version],
            recommendation="Disable SSLv2/SSLv3 support on this endpoint entirely; "
                            "require TLS 1.2 or newer.",
            domain="protocol",
            evidence_path="tls_handshake.version_negotiated",
        )]

    policy = _DEPRECATED_TLS_VERSION_POLICY.get(version)
    if policy:
        return [Finding(
            severity=SEVERITY_HIGH,
            title="Deprecated TLS version negotiated",
            evidence=f"version_negotiated={version}",
            policy_reference=policy,
            recommendation="Disable TLS 1.0/1.1 on this endpoint; require TLS 1.2 or newer.",
            domain="protocol",
            evidence_path="tls_handshake.version_negotiated",
        )]
    return []


def _check_cipher(tls: dict) -> list[Finding]:
    cipher = tls.get("cipher_suite_selected")
    if not cipher:
        return []

    upper = cipher.upper()
    matched = [p for p in _CRITICAL_CIPHER_PATTERNS if p in upper]
    if matched:
        return [Finding(
            severity=SEVERITY_CRITICAL,
            title="Critically weak cipher suite negotiated",
            evidence=f"cipher_suite_selected={cipher} (matches {', '.join(matched)})",
            policy_reference="BSI TR-02102-2",
            recommendation="Remove this cipher suite from the server's configuration; "
                            "it provides no meaningful confidentiality and/or authentication.",
            domain="cipher",
            evidence_path="tls_handshake.cipher_suite_selected",
        )]

    if tls.get("version_negotiated") == "TLS 1.2" and "CBC" in upper:
        return [Finding(
            severity=SEVERITY_MEDIUM,
            title="CBC-mode cipher suite negotiated on TLS 1.2",
            evidence=f"cipher_suite_selected={cipher}",
            policy_reference="NIST SP 800-52r2",
            recommendation="Prefer an AEAD cipher suite (e.g. AES-GCM or ChaCha20-Poly1305) "
                            "over CBC-mode on TLS 1.2 to avoid padding-oracle-style attacks.",
            domain="cipher",
            evidence_path="tls_handshake.cipher_suite_selected",
        )]
    return []


def _check_key_exchange(tls: dict) -> list[Finding]:
    if tls.get("key_exchange") == "RSA" and tls.get("forward_secrecy") is False:
        return [Finding(
            severity=SEVERITY_HIGH,
            title="Static RSA key exchange (no forward secrecy)",
            evidence=f"key_exchange=RSA, forward_secrecy=False "
                     f"(cipher_suite_selected={tls.get('cipher_suite_selected')})",
            policy_reference="NIST SP 800-52r2",
            recommendation="Configure the server to prefer ECDHE/DHE key exchange so a "
                            "later-compromised private key cannot retroactively decrypt "
                            "captured traffic.",
            domain="key_exchange",
            evidence_path="tls_handshake.forward_secrecy",
        )]
    return []


def _check_certificate(cert: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not cert or not cert.get("certificate_count"):
        return findings

    if cert.get("self_signed"):
        findings.append(Finding(
            severity=SEVERITY_HIGH,
            title="Self-signed certificate",
            evidence=f"issuer == subject ({cert.get('subject')})",
            policy_reference="RFC 5280",
            recommendation="Replace with a certificate issued by a trusted CA, or "
                            "explicitly distribute/pin this root to trusting clients.",
            domain="certificate",
            evidence_path="certificate.self_signed",
        ))

    if cert.get("chain_status") == "INVALID":
        findings.append(Finding(
            severity=SEVERITY_HIGH,
            title="Certificate chain does not cryptographically verify",
            evidence=f"chain_status=INVALID: {'; '.join(cert.get('notes') or [])}",
            policy_reference="RFC 5280",
            recommendation="Investigate the certificate chain configuration; a broken "
                            "chain is rejected or silently mistrusted by many clients.",
            domain="certificate",
            evidence_path="certificate.chain_status",
        ))
    elif cert.get("chain_status") == "NOT_OBSERVABLE" and not cert.get("self_signed"):
        findings.append(Finding(
            severity=SEVERITY_INFO,
            title="Certificate chain not fully observable",
            evidence=f"only {cert.get('certificate_count')} certificate(s) captured in this "
                     "handshake; issuing CA certificate(s) were not sent",
            policy_reference="RFC 5280",
            recommendation="Capture additional handshake traffic, or verify server-side "
                            "that intermediate certificates are configured to be sent to clients.",
            domain="certificate",
            evidence_path="certificate.chain_status",
        ))

    if cert.get("expired"):
        findings.append(Finding(
            severity=SEVERITY_HIGH,
            title="Certificate expired",
            evidence=f"not_valid_after={cert.get('not_valid_after')}",
            policy_reference="RFC 5280",
            recommendation="Renew the certificate immediately.",
            domain="certificate",
            evidence_path="certificate.expired",
        ))
    if cert.get("not_yet_valid"):
        findings.append(Finding(
            severity=SEVERITY_HIGH,
            title="Certificate not yet valid",
            evidence=f"not_valid_before={cert.get('not_valid_before')}",
            policy_reference="RFC 5280",
            recommendation="Correct the certificate's validity window or the server/client "
                            "clock skew.",
            domain="certificate",
            evidence_path="certificate.not_yet_valid",
        ))

    sig_algo = (cert.get("signature_algorithm") or "").upper()
    if "SHA1" in sig_algo or "MD5" in sig_algo:
        findings.append(Finding(
            severity=SEVERITY_HIGH,
            title="Weak certificate signature algorithm",
            evidence=f"signature_algorithm={cert.get('signature_algorithm')}",
            policy_reference="RFC 5280",
            recommendation="Re-issue the certificate signed with SHA-256 or stronger.",
            domain="certificate",
            evidence_path="certificate.signature_algorithm",
        ))

    if cert.get("key_algorithm") == "RSA" and (cert.get("key_length_bits") or 0) < _MIN_RSA_KEY_LENGTH_BITS:
        findings.append(Finding(
            severity=SEVERITY_HIGH,
            title="RSA key length below minimum",
            evidence=f"key_length_bits={cert.get('key_length_bits')}",
            policy_reference="NIST SP 800-52r2",
            recommendation=f"Re-issue the certificate with an RSA key of at least "
                            f"{_MIN_RSA_KEY_LENGTH_BITS} bits.",
            domain="certificate",
            evidence_path="certificate.key_length_bits",
        ))
    return findings


def _check_starttls(starttls: dict) -> list[Finding]:
    if starttls.get("status") == "PLAINTEXT_AFTER_ADVERTISEMENT":
        return [Finding(
            severity=SEVERITY_CRITICAL,
            title="STARTTLS stripping: plaintext continued after advertised upgrade",
            evidence=starttls.get("evidence", ""),
            policy_reference="RFC 3207, RFC 8314",
            recommendation="Enforce mandatory TLS (reject plaintext continuation after "
                            "STARTTLS/STLS) instead of opportunistic upgrade; this is a "
                            "classic STARTTLS-injection/stripping vector.",
            domain="starttls",
            evidence_path="starttls_negotiation.status",
        )]
    return []


_SEVERITY_SORT_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}


def _score_from_findings(findings: list[Finding]) -> float:
    total_weight = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return max(0.0, 100.0 - total_weight)


def _risk_level_for_score(score: float) -> str:
    for threshold, label in RISK_LEVEL_BANDS:
        if score >= threshold:
            return label
    return RISK_LEVEL_BANDS[-1][1]


def _risk_level(findings: list[Finding], score: float) -> str:
    level = _risk_level_for_score(score)
    for f in findings:
        floor = _SEVERITY_RISK_FLOOR.get(f.severity)
        if floor and _RISK_LEVEL_RANK[floor] > _RISK_LEVEL_RANK[level]:
            level = floor
    return level


def evaluate_session(tls_handshake: dict, certificate: dict, starttls: dict) -> RuleEngineResult:
    findings: list[Finding] = []
    findings.extend(_check_protocol_version(tls_handshake or {}))
    findings.extend(_check_cipher(tls_handshake or {}))
    findings.extend(_check_key_exchange(tls_handshake or {}))
    findings.extend(_check_certificate(certificate or {}))
    findings.extend(_check_starttls(starttls or {}))

    findings.sort(key=lambda f: _SEVERITY_SORT_ORDER[f.severity])

    score = _score_from_findings(findings)
    return RuleEngineResult(findings=findings, posture_score=score, risk_level=_risk_level(findings, score))
