#!/usr/bin/env python3
"""
SecureMailScope - comprehensive synthetic PCAP test generator.

Generates deterministic PCAPs covering:
  1. TLS 1.0 / 1.1 / 1.2 / 1.3
  2. Weak ciphers: 3DES, RC4, NULL/anonymous-style suites
  3. RSA, ECDHE and DHE cipher/key-exchange examples
  4. Real X.509 certificates:
       - valid
       - expired
       - wrong hostname
       - self-signed
       - weak RSA key
       - weak SHA-1 signature
       - incomplete-chain scenario
  5. STARTTLS failures
  6. TCP segmentation, retransmission, out-of-order packets
  7. Malformed/unusual TLS behavior
  8. ML-friendly labels in a manifest JSON

Important:
- This script creates synthetic traffic for deterministic parser/unit testing.
- Certificate scenarios use real DER-encoded X.509 certificates.
- It does NOT perform live network communication.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from struct import pack

from scapy.all import Ether, IP, TCP, Raw, wrpcap

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: cryptography. Install with: "
        "pip install scapy cryptography"
    ) from exc

try:
    from asn1crypto import x509 as asn1_x509
    from asn1crypto.keys import PublicKeyInfo
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: asn1crypto. Install with: "
        "pip install scapy cryptography asn1crypto"
    ) from exc


OUTPUT_DIR = Path("securemail_test_pcaps")
CERT_DIR = OUTPUT_DIR / "certificates"
MANIFEST_PATH = OUTPUT_DIR / "test_manifest.json"

CLIENT_IP = "10.10.10.10"
BASE_CLIENT_PORT = 41000


# ---------------------------------------------------------------------------
# TLS helpers
# ---------------------------------------------------------------------------

def tls_record(content_type, version, payload):
    """Build one TLS record."""
    return (
        bytes([content_type])
        + pack(">H", version)
        + pack(">H", len(payload))
        + payload
    )


def tls_handshake(handshake_type, body):
    """Build one TLS handshake message."""
    return bytes([handshake_type]) + len(body).to_bytes(3, "big") + body


def tls_alert(level=2, description=40):
    """Build a TLS alert record."""
    return tls_record(0x15, 0x0303, bytes([level, description]))


# Cipher-suite metadata used by the synthetic test cases.
CIPHERS = {
    0x000A: {
        "name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "key_exchange": "RSA",
        "strength": "weak",
    },
    0x0005: {
        "name": "TLS_RSA_WITH_RC4_128_SHA",
        "key_exchange": "RSA",
        "strength": "weak",
    },
    0x0000: {
        "name": "TLS_NULL_WITH_NULL_NULL",
        "key_exchange": "NULL",
        "strength": "critical",
    },
    0x0018: {
        "name": "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
        "key_exchange": "DHE-ANON",
        "strength": "critical",
    },
    0x002F: {
        "name": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "key_exchange": "RSA",
        "strength": "legacy",
    },
    0x009E: {
        "name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "key_exchange": "DHE",
        "strength": "strong",
    },
    0xC02F: {
        "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "key_exchange": "ECDHE",
        "strength": "strong",
    },
    0xC030: {
        "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "key_exchange": "ECDHE",
        "strength": "strong",
    },
    0x1301: {
        "name": "TLS_AES_128_GCM_SHA256",
        "key_exchange": "TLS1.3",
        "strength": "strong",
    },
    0x1302: {
        "name": "TLS_AES_256_GCM_SHA384",
        "key_exchange": "TLS1.3",
        "strength": "strong",
    },
    0x1303: {
        "name": "TLS_CHACHA20_POLY1305_SHA256",
        "key_exchange": "TLS1.3",
        "strength": "strong",
    },
}


def cipher_info(cipher_id):
    return CIPHERS.get(
        cipher_id,
        {
            "name": f"UNKNOWN_0x{cipher_id:04x}",
            "key_exchange": "UNKNOWN",
            "strength": "unknown",
        },
    )


def build_client_hello(
    tls_version=0x0303,
    cipher_suites=None,
    server_name="mail.example.test",
    malformed=False,
    unusual_cipher=None,
):
    """Create a deterministic synthetic ClientHello."""
    if cipher_suites is None:
        cipher_suites = [0xC02F]

    if unusual_cipher is not None:
        cipher_suites = [unusual_cipher] + list(cipher_suites)

    random_bytes = bytes(range(1, 33))
    session_id = b""

    cipher_bytes = b"".join(pack(">H", c) for c in cipher_suites)
    compression_methods = b"\x00"

    hostname = server_name.encode()
    sni_name = b"\x00" + pack(">H", len(hostname)) + hostname
    sni_list = pack(">H", len(sni_name)) + sni_name
    sni_extension = pack(">HH", 0x0000, len(sni_list)) + sni_list

    # supported_versions extension
    supported_versions = b"\x02" + pack(">H", tls_version)
    supported_versions_extension = (
        pack(">HH", 0x002B, len(supported_versions))
        + supported_versions
    )

    extensions = sni_extension + supported_versions_extension

    body = (
        pack(">H", tls_version)
        + random_bytes
        + bytes([len(session_id)])
        + session_id
        + pack(">H", len(cipher_bytes))
        + cipher_bytes
        + bytes([len(compression_methods)])
        + compression_methods
        + pack(">H", len(extensions))
        + extensions
    )

    handshake = tls_handshake(0x01, body)

    if malformed:
        # Deliberately corrupt the handshake length.
        return bytes([0x01, 0xFF, 0xFF, 0xFF]) + body[:8]

    return handshake


def build_server_hello(
    tls_version=0x0303,
    selected_cipher=0xC02F,
    malformed=False,
):
    """Create a deterministic synthetic ServerHello."""
    random_bytes = bytes(range(101, 133))
    session_id = b""
    extensions = b""

    if tls_version == 0x0304:
        legacy_record_version = 0x0303
        supported_versions = pack(">HH", 0x002B, 2) + pack(">H", 0x0304)
        extensions = supported_versions
    else:
        legacy_record_version = tls_version

    body = (
        pack(">H", legacy_record_version)
        + random_bytes
        + bytes([len(session_id)])
        + session_id
        + pack(">H", selected_cipher)
        + b"\x00"
        + pack(">H", len(extensions))
        + extensions
    )

    handshake = tls_handshake(0x02, body)

    if malformed:
        return handshake[:4] + b"\x00\x01"

    return handshake


def build_fake_tls_exchange(
    tls_version=0x0303,
    cipher_suites=None,
    selected_cipher=0xC02F,
    server_name="mail.example.test",
    malformed=False,
    unusual_cipher=None,
    include_certificate=False,
    certificate_der=None,
):
    """
    Build synthetic TLS handshake/application records.

    When certificate_der is supplied, a Certificate handshake is inserted
    between ServerHello and application data.
    """
    client_hello = build_client_hello(
        tls_version=tls_version,
        cipher_suites=cipher_suites,
        server_name=server_name,
        malformed=malformed,
        unusual_cipher=unusual_cipher,
    )

    record_version = 0x0303 if tls_version == 0x0304 else tls_version
    server_version = 0x0304 if tls_version == 0x0304 else tls_version

    server_hello = build_server_hello(
        tls_version=server_version,
        selected_cipher=selected_cipher,
        malformed=malformed,
    )

    records = [
        ("client", tls_record(0x16, record_version, client_hello)),
        ("server", tls_record(0x16, record_version, server_hello)),
    ]

    if include_certificate and certificate_der:
        # TLS Certificate handshake:
        # certificate_list_length(3) +
        # certificate_length(3) + certificate + extensions_length(2)
        cert_entry = (
            len(certificate_der).to_bytes(3, "big")
            + certificate_der
            + b"\x00\x00"
        )
        cert_body = (
            len(cert_entry).to_bytes(3, "big")
            + cert_entry
        )
        certificate_handshake = tls_handshake(0x0B, cert_body)
        records.append(
            ("server", tls_record(0x16, record_version, certificate_handshake))
        )

    if malformed:
        records.append(("server", tls_alert()))

    records.extend(
        [
            (
                "client",
                tls_record(0x17, record_version, b"\xAA" * 80),
            ),
            (
                "server",
                tls_record(0x17, record_version, b"\xBB" * 80),
            ),
        ]
    )

    return records


# ---------------------------------------------------------------------------
# TCP session helpers
# ---------------------------------------------------------------------------

class SyntheticTCPSession:
    def __init__(self, client_ip, server_ip, client_port, server_port):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port

        self.client_seq = 100000
        self.server_seq = 200000

        self.packets = []

    def packet(
        self,
        direction,
        payload=b"",
        flags="PA",
        seq_override=None,
    ):
        if direction == "client":
            src_ip = self.client_ip
            dst_ip = self.server_ip
            sport = self.client_port
            dport = self.server_port
            seq = self.client_seq if seq_override is None else seq_override
            ack = self.server_seq
        else:
            src_ip = self.server_ip
            dst_ip = self.client_ip
            sport = self.server_port
            dport = self.client_port
            seq = self.server_seq if seq_override is None else seq_override
            ack = self.client_seq

        tcp = TCP(
            sport=sport,
            dport=dport,
            flags=flags,
            seq=seq,
            ack=ack,
            window=64240,
        )

        packet = Ether() / IP(src=src_ip, dst=dst_ip) / tcp

        if payload:
            packet = packet / Raw(load=payload)

        self.packets.append(packet)

        # Do not advance sequence numbers for a deliberate retransmission.
        if seq_override is None:
            if direction == "client":
                self.client_seq += len(payload)
            else:
                self.server_seq += len(payload)

        return packet

    def handshake(self):
        self.packet("client", flags="S")
        self.server_seq += 1

        self.packet("server", flags="SA")
        self.client_seq += 1

        self.packet("client", flags="A")

    def close(self):
        self.packet("client", flags="FA")
        self.client_seq += 1

        self.packet("server", flags="FA")
        self.server_seq += 1

        self.packet("client", flags="A")


def text(value):
    return value.encode("ascii")


def add_tls_records(
    session,
    tls_packets,
    segment_size=None,
    retransmit=False,
    out_of_order=False,
):
    """Add TLS records, optionally segmented and/or reordered."""
    generated = []

    for direction, payload in tls_packets:
        if segment_size and len(payload) > segment_size:
            chunks = [
                payload[i:i + segment_size]
                for i in range(0, len(payload), segment_size)
            ]
        else:
            chunks = [payload]

        for chunk in chunks:
            generated.append((direction, chunk))

    if out_of_order and len(generated) >= 2:
        generated[0], generated[1] = generated[1], generated[0]

    for direction, payload in generated:
        pkt = session.packet(direction, payload)
        if retransmit and payload:
            # Exact duplicate TCP sequence number and payload.
            original_seq = (
                pkt[TCP].seq
            )
            session.packet(
                direction,
                payload,
                seq_override=original_seq,
            )


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

def make_rsa_key(bits=2048):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )


def make_certificate(
    common_name,
    key,
    issuer_key=None,
    issuer_name=None,
    not_before=None,
    not_after=None,
    hash_algorithm=hashes.SHA256(),
    self_signed=False,
):
    """Create a real X.509 certificate."""
    now = datetime.now(timezone.utc)

    if not_before is None:
        not_before = now - timedelta(minutes=5)

    if not_after is None:
        not_after = now + timedelta(days=365)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    if self_signed or issuer_key is None:
        issuer = subject
        signing_key = key
    else:
        issuer = issuer_name
        signing_key = issuer_key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(common_name)]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(
                ca=self_signed,
                path_length=None,
            ),
            critical=True,
        )
    )

    return builder.sign(
        private_key=signing_key,
        algorithm=hash_algorithm,
    )


def _asn1_time(dt):
    """asn1crypto Time is a CHOICE between UTCTime (years < 2050) and GeneralizedTime."""
    if dt.year < 2050:
        return asn1_x509.Time(name="utc_time", value=dt)
    return asn1_x509.Time(name="general_time", value=dt)


def make_sha1_signed_certificate(common_name, key, not_before=None, not_after=None):
    """Create a real, self-signed X.509 certificate with a SHA-1 signature.

    Modern `cryptography` (40+) hard-refuses to *create* SHA-1-signed certificates via
    CertificateBuilder.sign() (raises UnsupportedAlgorithm), even though SHA-1 certs are
    exactly the "weak signature" scenario this generator needs to produce. Signing raw
    bytes with SHA-1 is not restricted - only certificate creation is - so the
    TBSCertificate is built directly with asn1crypto (no such restriction) and then
    signed manually; the result is loaded back through `cryptography` so callers get an
    ordinary x509.Certificate object.
    """
    now = datetime.now(timezone.utc)

    if not_before is None:
        not_before = now - timedelta(minutes=5)

    if not_after is None:
        not_after = now + timedelta(days=365)

    public_key_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki = PublicKeyInfo.load(public_key_der)

    name = asn1_x509.Name.build(
        {
            "country_name": "IN",
            "organization_name": "SecureMailScope Test",
            "common_name": common_name,
        }
    )

    extensions = asn1_x509.Extensions(
        [
            {
                "extn_id": "subject_alt_name",
                "critical": False,
                "extn_value": asn1_x509.GeneralNames(
                    [asn1_x509.GeneralName(name="dns_name", value=common_name)]
                ),
            },
            {
                "extn_id": "basic_constraints",
                "critical": True,
                "extn_value": asn1_x509.BasicConstraints({"ca": False}),
            },
        ]
    )

    tbs = asn1_x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": x509.random_serial_number(),
            "signature": {"algorithm": "sha1_rsa"},
            "issuer": name,
            "validity": {
                "not_before": _asn1_time(not_before),
                "not_after": _asn1_time(not_after),
            },
            "subject": name,
            "subject_public_key_info": spki,
            "extensions": extensions,
        }
    )

    tbs_der = tbs.dump()
    signature = key.sign(tbs_der, rsa_padding.PKCS1v15(), hashes.SHA1())

    cert = asn1_x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": {"algorithm": "sha1_rsa"},
            "signature_value": signature,
        }
    )

    return x509.load_der_x509_certificate(cert.dump())


def write_cert(name, cert):
    der = cert.public_bytes(serialization.Encoding.DER)
    pem = cert.public_bytes(serialization.Encoding.PEM)

    (CERT_DIR / f"{name}.der").write_bytes(der)
    (CERT_DIR / f"{name}.pem").write_bytes(pem)

    return der


def generate_certificates():
    """Generate all certificate scenarios and return DER bytes."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)

    # 1. Valid certificate
    valid_key = make_rsa_key(2048)
    valid_cert = make_certificate(
        "mail.example.test",
        valid_key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
    )

    # 2. Expired certificate
    expired_key = make_rsa_key(2048)
    expired_cert = make_certificate(
        "expired.example.test",
        expired_key,
        not_before=now - timedelta(days=365),
        not_after=now - timedelta(days=1),
    )

    # 3. Wrong hostname
    wrong_host_key = make_rsa_key(2048)
    wrong_host_cert = make_certificate(
        "other.example.test",
        wrong_host_key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
    )

    # 4. Self-signed
    self_signed_key = make_rsa_key(2048)
    self_signed_cert = make_certificate(
        "selfsigned.example.test",
        self_signed_key,
        self_signed=True,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
    )

    # 5. Weak key length
    weak_key = make_rsa_key(1024)
    weak_key_cert = make_certificate(
        "weak-key.example.test",
        weak_key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
    )

    # 6. Weak signature algorithm
    sha1_key = make_rsa_key(2048)
    sha1_cert = make_sha1_signed_certificate(
        "sha1.example.test",
        sha1_key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
    )

    # 7. Incomplete chain:
    # root -> intermediate -> leaf are created, but the PCAP carries only leaf.
    root_key = make_rsa_key(2048)
    root_cert = make_certificate(
        "SecureMailScope Root CA",
        root_key,
        self_signed=True,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=3650),
    )

    intermediate_key = make_rsa_key(2048)
    intermediate_cert = make_certificate(
        "SecureMailScope Intermediate CA",
        intermediate_key,
        issuer_key=root_key,
        issuer_name=root_cert.subject,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=2000),
        self_signed=False,
    )

    leaf_chain_key = make_rsa_key(2048)
    leaf_chain_cert = make_certificate(
        "incomplete-chain.example.test",
        leaf_chain_key,
        issuer_key=intermediate_key,
        issuer_name=intermediate_cert.subject,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        self_signed=False,
    )

    certs = {
        "valid": valid_cert,
        "expired": expired_cert,
        "wrong_hostname": wrong_host_cert,
        "self_signed": self_signed_cert,
        "weak_key": weak_key_cert,
        "weak_signature": sha1_cert,
        "incomplete_chain": leaf_chain_cert,
    }

    return {name: write_cert(name, cert) for name, cert in certs.items()}


# ---------------------------------------------------------------------------
# PCAP scenarios
# ---------------------------------------------------------------------------

def make_session(server_ip, port, client_port):
    session = SyntheticTCPSession(
        CLIENT_IP,
        server_ip,
        client_port,
        port,
    )
    session.handshake()
    return session


def smtp_starttls(
    server_ip,
    client_port,
    tls_version,
    cipher,
    filename_label,
    cert_der=None,
    server_name="mail.example.test",
    segment=False,
    retransmit=False,
    out_of_order=False,
):
    session = make_session(server_ip, 25, client_port)

    session.packet(
        "server",
        text("220 mail.example.test ESMTP SecureMailScope\r\n"),
    )

    session.packet(
        "client",
        text(
            "EHLO client.example.test\r\n"
            "MAIL FROM:<alice@example.test>\r\n"
            "RCPT TO:<bob@example.test>\r\n"
            "STARTTLS\r\n"
        ),
    )

    session.packet(
        "server",
        text(
            "250-mail.example.test\r\n"
            "250-STARTTLS\r\n"
            "220 2.0.0 Ready to start TLS\r\n"
        ),
    )

    tls_packets = build_fake_tls_exchange(
        tls_version=tls_version,
        cipher_suites=[cipher],
        selected_cipher=cipher,
        server_name=server_name,
        include_certificate=cert_der is not None,
        certificate_der=cert_der,
    )

    add_tls_records(
        session,
        tls_packets,
        segment_size=40 if segment else None,
        retransmit=retransmit,
        out_of_order=out_of_order,
    )

    session.close()
    return session.packets, {
        "filename": filename_label,
        "protocol": "SMTP",
        "scenario": "STARTTLS",
        "tls_version": f"0x{tls_version:04x}",
        "cipher": cipher_info(cipher)["name"],
        "key_exchange": cipher_info(cipher)["key_exchange"],
        "label": "safe" if cipher_info(cipher)["strength"] == "strong" else "weak",
    }


def imap_starttls_failure(
    server_ip,
    client_port,
    failure_type,
):
    session = make_session(server_ip, 143, client_port)

    session.packet(
        "server",
        text("* OK IMAP4rev1 mail.example.test ready\r\n"),
    )

    session.packet(
        "client",
        text("a001 CAPABILITY\r\n"),
    )

    session.packet(
        "server",
        text(
            "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n"
            "a001 OK CAPABILITY completed\r\n"
        ),
    )

    if failure_type == "not_used":
        client_data = (
            "a002 LOGIN testuser Password123!\r\n"
        )
        server_data = "a002 OK LOGIN completed\r\n"

    elif failure_type == "rejected":
        client_data = "a002 STARTTLS\r\n"
        server_data = "a002 NO STARTTLS unavailable\r\n"

    else:
        client_data = (
            "a002 STARTTLS\r\n"
            "a003 LOGIN victim Password123!\r\n"
        )
        server_data = (
            "a002 OK Begin TLS negotiation now\r\n"
            "a003 OK LOGIN completed\r\n"
        )

    session.packet("client", text(client_data))
    session.packet("server", text(server_data))

    session.close()

    return session.packets, {
        "protocol": "IMAP",
        "scenario": f"STARTTLS_{failure_type}",
        "label": "weak",
    }


def pop3_plaintext(server_ip, client_port):
    session = make_session(server_ip, 110, client_port)

    session.packet(
        "server",
        text("+OK POP3 server ready\r\n"),
    )

    session.packet(
        "client",
        text(
            "USER testuser\r\n"
            "PASS SuperSecretPassword123!\r\n"
            "STAT\r\n"
        ),
    )

    session.packet(
        "server",
        text(
            "+OK User accepted\r\n"
            "+OK 4 2048\r\n"
        ),
    )

    session.close()

    return session.packets, {
        "protocol": "POP3",
        "scenario": "PLAINTEXT_CREDENTIALS",
        "label": "weak",
    }


def smtps_tls13(server_ip, client_port, cert_der):
    session = make_session(server_ip, 465, client_port)

    tls_packets = build_fake_tls_exchange(
        tls_version=0x0304,
        cipher_suites=[0x1301, 0x1302, 0x1303],
        selected_cipher=0x1301,
        server_name="mail.example.test",
        include_certificate=True,
        certificate_der=cert_der,
    )

    add_tls_records(session, tls_packets)
    session.close()

    return session.packets, {
        "protocol": "SMTPS",
        "scenario": "IMPLICIT_TLS13",
        "tls_version": "0x0304",
        "cipher": cipher_info(0x1301)["name"],
        "key_exchange": "TLS1.3",
        "label": "safe",
    }


def malformed_tls(server_ip, client_port):
    session = make_session(server_ip, 2525, client_port)

    tls_packets = build_fake_tls_exchange(
        tls_version=0x0399,
        cipher_suites=[0xC02F],
        selected_cipher=0xC02F,
        malformed=True,
    )

    add_tls_records(session, tls_packets)
    session.close()

    return session.packets, {
        "protocol": "SMTP-like",
        "scenario": "MALFORMED_TLS",
        "tls_version": "0x0399",
        "label": "anomalous",
    }


def unusual_cipher(server_ip, client_port):
    session = make_session(server_ip, 2526, client_port)

    unusual = 0xFEFE

    tls_packets = build_fake_tls_exchange(
        tls_version=0x0303,
        cipher_suites=[0xC02F],
        selected_cipher=unusual,
        unusual_cipher=unusual,
    )

    add_tls_records(session, tls_packets)
    session.close()

    return session.packets, {
        "protocol": "SMTP-like",
        "scenario": "UNUSUAL_CIPHER",
        "tls_version": "0x0303",
        "cipher": cipher_info(unusual)["name"],
        "label": "anomalous",
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def write_pcap(filename, packets):
    path = OUTPUT_DIR / filename
    wrpcap(str(path), packets)
    print(f"[+] Created {path} - {len(packets)} packets")
    return path


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    certificates = generate_certificates()
    manifest = []

    # TLS 1.0 + 3DES/RSA
    packets, meta = smtp_starttls(
        "10.10.10.20",
        BASE_CLIENT_PORT,
        0x0301,
        0x000A,
        "01_tls10_3des_rsa.pcap",
        cert_der=certificates["valid"],
    )
    write_pcap(meta["filename"], packets)
    manifest.append(meta)

    # TLS 1.1 + RC4/RSA
    packets, meta = smtp_starttls(
        "10.10.10.21",
        BASE_CLIENT_PORT + 1,
        0x0302,
        0x0005,
        "02_tls11_rc4_rsa.pcap",
        cert_der=certificates["valid"],
    )
    write_pcap(meta["filename"], packets)
    manifest.append(meta)

    # TLS 1.2 + ECDHE/RSA
    packets, meta = smtp_starttls(
        "10.10.10.22",
        BASE_CLIENT_PORT + 2,
        0x0303,
        0xC02F,
        "03_tls12_ecdhe_rsa_safe.pcap",
        cert_der=certificates["valid"],
    )
    write_pcap(meta["filename"], packets)
    manifest.append(meta)

    # TLS 1.2 + DHE/RSA
    packets, meta = smtp_starttls(
        "10.10.10.23",
        BASE_CLIENT_PORT + 3,
        0x0303,
        0x009E,
        "04_tls12_dhe_rsa.pcap",
        cert_der=certificates["valid"],
    )
    write_pcap(meta["filename"], packets)
    manifest.append(meta)

    # TLS 1.2 + NULL/NULL synthetic edge case
    packets, meta = smtp_starttls(
        "10.10.10.24",
        BASE_CLIENT_PORT + 4,
        0x0303,
        0x0000,
        "05_tls12_null_cipher.pcap",
        cert_der=certificates["weak_signature"],
    )
    meta["label"] = "weak"
    write_pcap(meta["filename"], packets)
    manifest.append(meta)

    # TLS 1.2 + anonymous 3DES synthetic edge case
    packets, meta = smtp_starttls(
        "10.10.10.25",
        BASE_CLIENT_PORT + 5,
        0x0303,
        0x0018,
        "06_tls12_dh_anon_3des.pcap",
        cert_der=certificates["self_signed"],
    )
    meta["label"] = "weak"
    write_pcap(meta["filename"], packets)
    manifest.append(meta)

    # TLS 1.3
    packets, meta = smtps_tls13(
        "10.10.10.26",
        BASE_CLIENT_PORT + 6,
        certificates["valid"],
    )
    write_pcap("07_tls13_safe.pcap", packets)
    meta["filename"] = "07_tls13_safe.pcap"
    manifest.append(meta)

    # Certificate scenarios
    certificate_cases = [
        ("08_cert_expired.pcap", "expired", "CERT_EXPIRED"),
        ("09_cert_wrong_hostname.pcap", "wrong_hostname", "CERT_WRONG_HOSTNAME"),
        ("10_cert_self_signed.pcap", "self_signed", "CERT_SELF_SIGNED"),
        ("11_cert_weak_key.pcap", "weak_key", "CERT_WEAK_KEY"),
        ("12_cert_weak_signature_sha1.pcap", "weak_signature", "CERT_WEAK_SIGNATURE"),
        ("13_cert_incomplete_chain.pcap", "incomplete_chain", "CERT_INCOMPLETE_CHAIN"),
    ]

    for index, (filename, cert_name, scenario) in enumerate(certificate_cases):
        packets, meta = smtp_starttls(
            f"10.10.11.{index + 1}",
            BASE_CLIENT_PORT + 20 + index,
            0x0303,
            0xC02F,
            filename,
            cert_der=certificates[cert_name],
            server_name=(
                "mail.example.test"
                if cert_name != "wrong_hostname"
                else "mail.example.test"
            ),
        )
        meta["scenario"] = scenario
        meta["label"] = "weak"
        write_pcap(filename, packets)
        manifest.append(meta)

    # STARTTLS failures
    for index, failure_type in enumerate(
        ["not_used", "rejected", "plaintext_after_advertisement"]
    ):
        packets, meta = imap_starttls_failure(
            f"10.10.12.{index + 1}",
            BASE_CLIENT_PORT + 40 + index,
            failure_type,
        )
        filename = f"14_starttls_{failure_type}.pcap"
        write_pcap(filename, packets)
        meta["filename"] = filename
        manifest.append(meta)

    # Plaintext POP3
    packets, meta = pop3_plaintext(
        "10.10.13.1",
        BASE_CLIENT_PORT + 50,
    )
    write_pcap("15_pop3_plaintext_credentials.pcap", packets)
    meta["filename"] = "15_pop3_plaintext_credentials.pcap"
    manifest.append(meta)

    # TCP segmentation
    packets, meta = smtp_starttls(
        "10.10.14.1",
        BASE_CLIENT_PORT + 60,
        0x0303,
        0xC02F,
        "16_tcp_segmented_tls_handshake.pcap",
        cert_der=certificates["valid"],
        segment=True,
    )
    meta["scenario"] = "TCP_SEGMENTED_TLS_HANDSHAKE"
    write_pcap(meta["filename"], packets)
    manifest.append(meta)

    # TCP retransmission
    packets, meta = smtp_starttls(
        "10.10.14.2",
        BASE_CLIENT_PORT + 61,
        0x0303,
        0xC02F,
        "17_tcp_retransmission.pcap",
        cert_der=certificates["valid"],
        retransmit=True,
    )
    meta["scenario"] = "TCP_RETRANSMISSION"
    write_pcap(meta["filename"], packets)
    manifest.append(meta)

    # TCP out-of-order
    packets, meta = smtp_starttls(
        "10.10.14.3",
        BASE_CLIENT_PORT + 62,
        0x0303,
        0xC02F,
        "18_tcp_out_of_order.pcap",
        cert_der=certificates["valid"],
        out_of_order=True,
    )
    meta["scenario"] = "TCP_OUT_OF_ORDER"
    write_pcap(meta["filename"], packets)
    manifest.append(meta)

    # Malformed TLS
    packets, meta = malformed_tls(
        "10.10.15.1",
        BASE_CLIENT_PORT + 70,
    )
    write_pcap("19_malformed_tls.pcap", packets)
    meta["filename"] = "19_malformed_tls.pcap"
    manifest.append(meta)

    # Unexpected TLS version
    packets, meta = smtp_starttls(
        "10.10.15.2",
        BASE_CLIENT_PORT + 71,
        0x0399,
        0xC02F,
        "20_unexpected_tls_version.pcap",
        cert_der=certificates["valid"],
    )
    meta["scenario"] = "UNEXPECTED_TLS_VERSION"
    meta["label"] = "anomalous"
    write_pcap(meta["filename"], packets)
    manifest.append(meta)

    # Unusual cipher negotiation
    packets, meta = unusual_cipher(
        "10.10.15.3",
        BASE_CLIENT_PORT + 72,
    )
    write_pcap("21_unusual_cipher.pcap", packets)
    meta["filename"] = "21_unusual_cipher.pcap"
    manifest.append(meta)

    # ------------------------------------------------------------------
    # Multiple sessions in one PCAP
    # ------------------------------------------------------------------
    combined = []

    for filename, builder in [
        ("combined", lambda: smtp_starttls(
            "10.10.20.1",
            42001,
            0x0303,
            0xC02F,
            "combined_safe",
            cert_der=certificates["valid"],
        )[0]),
        ("combined", lambda: smtp_starttls(
            "10.10.20.2",
            42002,
            0x0301,
            0x000A,
            "combined_weak",
            cert_der=certificates["expired"],
        )[0]),
        ("combined", lambda: pop3_plaintext(
            "10.10.20.3",
            42003,
        )[0]),
    ]:
        combined.extend(builder())

    write_pcap("22_multiple_sessions_combined.pcap", combined)

    manifest.append(
        {
            "filename": "22_multiple_sessions_combined.pcap",
            "scenario": "MULTIPLE_SESSIONS",
            "label": "mixed",
            "contains": ["safe", "weak"],
        }
    )

    # ------------------------------------------------------------------
    # ML-oriented labels
    # ------------------------------------------------------------------
    safe_files = [
        "03_tls12_ecdhe_rsa_safe.pcap",
        "04_tls12_dhe_rsa.pcap",
        "07_tls13_safe.pcap",
        "16_tcp_segmented_tls_handshake.pcap",
    ]

    weak_files = [
        "01_tls10_3des_rsa.pcap",
        "02_tls11_rc4_rsa.pcap",
        "05_tls12_null_cipher.pcap",
        "06_tls12_dh_anon_3des.pcap",
        "08_cert_expired.pcap",
        "09_cert_wrong_hostname.pcap",
        "10_cert_self_signed.pcap",
        "11_cert_weak_key.pcap",
        "12_cert_weak_signature_sha1.pcap",
        "13_cert_incomplete_chain.pcap",
        "14_starttls_not_used.pcap",
        "14_starttls_rejected.pcap",
        "14_starttls_plaintext_after_advertisement.pcap",
        "15_pop3_plaintext_credentials.pcap",
    ]

    anomalous_files = [
        "17_tcp_retransmission.pcap",
        "18_tcp_out_of_order.pcap",
        "19_malformed_tls.pcap",
        "20_unexpected_tls_version.pcap",
        "21_unusual_cipher.pcap",
    ]

    ml_dataset = {
        "safe": safe_files,
        "weak": weak_files,
        "anomalous": anomalous_files,
        "mixed": ["22_multiple_sessions_combined.pcap"],
    }

    manifest_document = {
        "project": "SecureMailScope",
        "purpose": "Synthetic PCAP test dataset",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "certificate_directory": str(CERT_DIR),
        "cases": manifest,
        "ml_dataset": ml_dataset,
        "notes": [
            "Traffic is synthetic and intended for parser/unit/integration testing.",
            "Certificates are real X.509 DER certificates.",
            "The incomplete-chain PCAP intentionally carries only the leaf certificate.",
            "Some NULL/anonymous cipher identifiers are synthetic edge cases.",
            "Do not use embedded example credentials outside the test environment.",
        ],
    }

    MANIFEST_PATH.write_text(
        json.dumps(manifest_document, indent=2),
        encoding="utf-8",
    )

    print()
    print("[+] PCAP generation completed.")
    print(f"[+] Output directory: {OUTPUT_DIR.resolve()}")
    print(f"[+] Manifest: {MANIFEST_PATH.resolve()}")
    print(f"[+] Certificates: {CERT_DIR.resolve()}")


if __name__ == "__main__":
    main()
