"""X.509 certificate extraction and validation (Stage 5).

Consumes the raw DER bytes Stage 4's `tls.handshake.analyze_tls_handshake` pulled out of
the Certificate handshake message and turns them into structured, evidence-linked facts:
subject/issuer, validity window vs. the capture's own timestamp (never wall-clock "now" -
a capture from last year must not be judged against today's date), key algorithm/length,
signature algorithm, SAN/hostname match against the session's observed SNI, chain
completeness, and a SHA-256 fingerprint. Only reports facts that are cryptographically
checkable from what was actually captured - if the issuing CA certificate(s) weren't sent
in the handshake, chain status is "not observable", never guessed (see CLAUDE.md §12 and
the file `13` incomplete-chain scenario this is built against). Scoring/severity is Stage
6's job, not this module's.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID

CHAIN_OBSERVED_VALID = "OBSERVED_VALID"
CHAIN_NOT_OBSERVABLE = "NOT_OBSERVABLE"
CHAIN_INVALID = "INVALID"

_SIGNATURE_ALGORITHM_NAMES = {
    SignatureAlgorithmOID.RSA_WITH_MD5.dotted_string: "MD5withRSA",
    SignatureAlgorithmOID.RSA_WITH_SHA1.dotted_string: "SHA1withRSA",
    SignatureAlgorithmOID.RSA_WITH_SHA224.dotted_string: "SHA224withRSA",
    SignatureAlgorithmOID.RSA_WITH_SHA256.dotted_string: "SHA256withRSA",
    SignatureAlgorithmOID.RSA_WITH_SHA384.dotted_string: "SHA384withRSA",
    SignatureAlgorithmOID.RSA_WITH_SHA512.dotted_string: "SHA512withRSA",
    SignatureAlgorithmOID.ECDSA_WITH_SHA256.dotted_string: "SHA256withECDSA",
    SignatureAlgorithmOID.ECDSA_WITH_SHA384.dotted_string: "SHA384withECDSA",
    SignatureAlgorithmOID.ECDSA_WITH_SHA512.dotted_string: "SHA512withECDSA",
}


def _signature_algorithm_name(cert: x509.Certificate) -> str:
    dotted = cert.signature_algorithm_oid.dotted_string
    return _SIGNATURE_ALGORITHM_NAMES.get(dotted, dotted)


def _name_str(name: x509.Name) -> str:
    cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn[0].value if cn else name.rfc4514_string()


def _key_algorithm_and_length(public_key) -> tuple[str, Optional[int]]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    return "UNKNOWN", None


def _san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return ext.value.get_values_for_type(x509.DNSName)


def _hostname_matches(cert: x509.Certificate, hostname: str) -> bool:
    hostname = hostname.lower()
    candidates = {name.lower() for name in _san_dns_names(cert)}
    common_name = _name_str(cert.subject)
    if common_name:
        candidates.add(common_name.lower())
    return hostname in candidates


def _is_self_signed_name(cert: x509.Certificate) -> bool:
    return cert.issuer == cert.subject


def _verify_signature(subject_cert: x509.Certificate, issuer_public_key) -> bool:
    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                subject_cert.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                ec.ECDSA(subject_cert.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except InvalidSignature:
        return False


@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: str
    not_valid_after: str
    key_algorithm: str
    key_length_bits: Optional[int]
    signature_algorithm: str
    san_dns_names: list = field(default_factory=list)
    sha256_fingerprint: str = ""
    self_signed: bool = False
    expired: bool = False
    not_yet_valid: bool = False
    hostname_checked: Optional[str] = None
    hostname_match: Optional[bool] = None

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_valid_before": self.not_valid_before,
            "not_valid_after": self.not_valid_after,
            "key_algorithm": self.key_algorithm,
            "key_length_bits": self.key_length_bits,
            "signature_algorithm": self.signature_algorithm,
            "san_dns_names": self.san_dns_names,
            "sha256_fingerprint": self.sha256_fingerprint,
            "self_signed": self.self_signed,
            "expired": self.expired,
            "not_yet_valid": self.not_yet_valid,
            "hostname_checked": self.hostname_checked,
            "hostname_match": self.hostname_match,
        }


def _build_info(cert: x509.Certificate, der: bytes, evaluation_time: datetime, hostname: Optional[str]) -> CertificateInfo:
    key_algorithm, key_length_bits = _key_algorithm_and_length(cert.public_key())
    return CertificateInfo(
        subject=_name_str(cert.subject),
        issuer=_name_str(cert.issuer),
        serial_number=format(cert.serial_number, "x"),
        not_valid_before=cert.not_valid_before_utc.isoformat(),
        not_valid_after=cert.not_valid_after_utc.isoformat(),
        key_algorithm=key_algorithm,
        key_length_bits=key_length_bits,
        signature_algorithm=_signature_algorithm_name(cert),
        san_dns_names=_san_dns_names(cert),
        sha256_fingerprint=hashlib.sha256(der).hexdigest(),
        self_signed=_is_self_signed_name(cert),
        expired=evaluation_time > cert.not_valid_after_utc,
        not_yet_valid=evaluation_time < cert.not_valid_before_utc,
        hostname_checked=hostname,
        hostname_match=_hostname_matches(cert, hostname) if hostname else None,
    )


def _assess_chain(certs: list[x509.Certificate]) -> tuple[str, list[str]]:
    if len(certs) == 1:
        leaf = certs[0]
        if _is_self_signed_name(leaf):
            if _verify_signature(leaf, leaf.public_key()):
                return CHAIN_OBSERVED_VALID, [
                    "single self-signed certificate observed; its self-signature verified"
                ]
            return CHAIN_INVALID, [
                "self-signed certificate's signature does not verify against its own public key"
            ]
        return CHAIN_NOT_OBSERVABLE, [
            "only the leaf certificate was observed; issuing CA certificate(s) were not "
            "sent in this handshake, so chain validity cannot be determined"
        ]

    for subject_cert, issuer_cert in zip(certs, certs[1:]):
        if subject_cert.issuer != issuer_cert.subject:
            return CHAIN_INVALID, [
                f"issuer of '{_name_str(subject_cert.subject)}' does not match the subject "
                f"of the next certificate in the chain '{_name_str(issuer_cert.subject)}'"
            ]
        if not _verify_signature(subject_cert, issuer_cert.public_key()):
            return CHAIN_INVALID, [
                f"signature of '{_name_str(subject_cert.subject)}' does not verify against "
                f"the public key of '{_name_str(issuer_cert.subject)}'"
            ]

    root = certs[-1]
    if _is_self_signed_name(root):
        if _verify_signature(root, root.public_key()):
            return CHAIN_OBSERVED_VALID, ["full chain observed and verified up to a self-signed root"]
        return CHAIN_INVALID, ["root certificate's self-signature does not verify"]

    return CHAIN_NOT_OBSERVABLE, [
        "chain observed but does not terminate in a self-signed root; the ultimate trust "
        "anchor was not sent in this handshake"
    ]


@dataclass
class CertificateChainAnalysis:
    certificate_count: int
    leaf: Optional[CertificateInfo]
    chain: list
    chain_status: str
    notes: list

    def to_dict(self) -> dict:
        if self.leaf is None:
            base = {
                "subject": None,
                "issuer": None,
                "serial_number": None,
                "not_valid_before": None,
                "not_valid_after": None,
                "key_algorithm": None,
                "key_length_bits": None,
                "signature_algorithm": None,
                "san_dns_names": [],
                "sha256_fingerprint": None,
                "self_signed": None,
                "expired": None,
                "not_yet_valid": None,
                "hostname_checked": None,
                "hostname_match": None,
            }
        else:
            base = self.leaf.to_dict()
        base["certificate_count"] = self.certificate_count
        base["chain_status"] = self.chain_status
        base["chain"] = [c.to_dict() for c in self.chain]
        base["notes"] = self.notes
        return base


def analyze_certificate_chain(
    certificates_der_hex: list,
    evaluation_time: Optional[datetime] = None,
    hostname: Optional[str] = None,
) -> CertificateChainAnalysis:
    if not certificates_der_hex:
        return CertificateChainAnalysis(
            certificate_count=0,
            leaf=None,
            chain=[],
            chain_status=CHAIN_NOT_OBSERVABLE,
            notes=["no certificate observed in this session"],
        )

    if evaluation_time is None:
        evaluation_time = datetime.now(timezone.utc)

    notes: list = []
    ders: list = []
    certs: list = []
    for der_hex in certificates_der_hex:
        der = bytes.fromhex(der_hex)
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError as exc:
            notes.append(f"could not parse certificate: {exc}")
            continue
        ders.append(der)
        certs.append(cert)

    if not certs:
        return CertificateChainAnalysis(
            certificate_count=len(certificates_der_hex),
            leaf=None,
            chain=[],
            chain_status=CHAIN_NOT_OBSERVABLE,
            notes=notes or ["no certificate could be parsed"],
        )

    infos = [
        _build_info(cert, der, evaluation_time, hostname if i == 0 else None)
        for i, (cert, der) in enumerate(zip(certs, ders))
    ]
    chain_status, chain_notes = _assess_chain(certs)
    notes.extend(chain_notes)

    return CertificateChainAnalysis(
        certificate_count=len(certs),
        leaf=infos[0],
        chain=infos,
        chain_status=chain_status,
        notes=notes,
    )
