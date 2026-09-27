"""TLS handshake message parsing and orchestration (Stage 4).

Parses ClientHello, ServerHello and Certificate handshake messages against the exact wire
format `genny.py` produces (see CLAUDE.md §5/§12 - it's the ground-truth fixture source),
and rolls the result into a single `TLSHandshakeInfo` ready to merge into a session's API
response. Certificate messages only yield raw DER bytes here; validating them is Stage 5.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .cipher_suites import (
    alert_description_name,
    cipher_info,
    has_forward_secrecy,
    tls_version_name,
)
from .records import extract_alerts, extract_handshake_stream, split_handshake_messages, split_tls_records

HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
HANDSHAKE_TYPE_SERVER_HELLO = 0x02
HANDSHAKE_TYPE_CERTIFICATE = 0x0B

_EXT_SERVER_NAME = 0x0000
_EXT_SUPPORTED_VERSIONS = 0x002B


def _parse_extensions(data: bytes) -> dict:
    sni = None
    supported_versions: list[int] = []
    offset = 0
    while offset + 4 <= len(data):
        ext_type = int.from_bytes(data[offset:offset + 2], "big")
        ext_len = int.from_bytes(data[offset + 2:offset + 4], "big")
        ext_data = data[offset + 4:offset + 4 + ext_len]
        if len(ext_data) < ext_len:
            break

        if ext_type == _EXT_SERVER_NAME and len(ext_data) >= 5:
            name_len = int.from_bytes(ext_data[3:5], "big")
            sni = ext_data[5:5 + name_len].decode("ascii", errors="replace")
        elif ext_type == _EXT_SUPPORTED_VERSIONS:
            if len(ext_data) == 2:
                # ServerHello form: the extension body IS the negotiated version.
                supported_versions = [int.from_bytes(ext_data, "big")]
            elif len(ext_data) >= 1:
                # ClientHello form: 1-byte list length + 2-byte version entries.
                count = ext_data[0] // 2
                supported_versions = [
                    int.from_bytes(ext_data[1 + 2 * i:3 + 2 * i], "big") for i in range(count)
                ]

        offset += 4 + ext_len

    return {"sni": sni, "supported_versions": supported_versions}


def parse_client_hello(body: bytes) -> dict:
    if len(body) < 2 + 32 + 1:
        return {}

    legacy_version = int.from_bytes(body[0:2], "big")
    offset = 2 + 32

    session_id_len = body[offset]
    offset += 1 + session_id_len

    if offset + 2 > len(body):
        return {"legacy_version": legacy_version}
    cipher_len = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    cipher_suites = [
        int.from_bytes(body[offset + 2 * i:offset + 2 * i + 2], "big") for i in range(cipher_len // 2)
    ]
    offset += cipher_len

    if offset >= len(body):
        return {"legacy_version": legacy_version, "cipher_suites_offered": cipher_suites}
    compression_len = body[offset]
    offset += 1 + compression_len

    extensions = {}
    if offset + 2 <= len(body):
        ext_total_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        extensions = _parse_extensions(body[offset:offset + ext_total_len])

    offered_version = (extensions.get("supported_versions") or [None])[0] or legacy_version
    if extensions.get("supported_versions"):
        offered_version = max(extensions["supported_versions"])

    return {
        "legacy_version": legacy_version,
        "offered_version": offered_version,
        "cipher_suites_offered": cipher_suites,
        "sni": extensions.get("sni"),
    }


def parse_server_hello(body: bytes) -> dict:
    if len(body) < 2 + 32 + 1 + 2 + 1:
        return {}

    legacy_version = int.from_bytes(body[0:2], "big")
    offset = 2 + 32

    session_id_len = body[offset]
    offset += 1 + session_id_len

    if offset + 2 > len(body):
        return {"legacy_version": legacy_version}
    selected_cipher = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2 + 1  # cipher suite + compression method

    extensions = {}
    if offset + 2 <= len(body):
        ext_total_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        extensions = _parse_extensions(body[offset:offset + ext_total_len])

    negotiated_version = (extensions.get("supported_versions") or [None])[0] or legacy_version

    return {
        "legacy_version": legacy_version,
        "negotiated_version": negotiated_version,
        "cipher_suite_selected": selected_cipher,
    }


def parse_certificate_message(body: bytes) -> list[bytes]:
    if len(body) < 3:
        return []

    list_len = int.from_bytes(body[0:3], "big")
    data = body[3:3 + list_len]

    certs = []
    offset = 0
    while offset + 3 <= len(data):
        cert_len = int.from_bytes(data[offset:offset + 3], "big")
        offset += 3
        cert_der = data[offset:offset + cert_len]
        if len(cert_der) < cert_len:
            break
        offset += cert_len
        certs.append(cert_der)
        if offset + 2 <= len(data):
            ext_len = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2 + ext_len
    return certs


@dataclass
class TLSHandshakeInfo:
    handshake_observed: bool = False
    client_hello_seen: bool = False
    server_hello_seen: bool = False
    version_offered: Optional[str] = None
    version_negotiated: Optional[str] = None
    cipher_suites_offered: list = field(default_factory=list)
    cipher_suite_selected: Optional[str] = None
    key_exchange: Optional[str] = None
    forward_secrecy: Optional[bool] = None
    sni: Optional[str] = None
    certificates_der_hex: list = field(default_factory=list)
    alerts: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "handshake_observed": self.handshake_observed,
            "client_hello_seen": self.client_hello_seen,
            "server_hello_seen": self.server_hello_seen,
            "version_offered": self.version_offered,
            "version_negotiated": self.version_negotiated,
            "cipher_suites_offered": self.cipher_suites_offered,
            "cipher_suite_selected": self.cipher_suite_selected,
            "key_exchange": self.key_exchange,
            "forward_secrecy": self.forward_secrecy,
            "sni": self.sni,
            "certificate_count": len(self.certificates_der_hex),
            "certificates_der_hex": self.certificates_der_hex,
            "alerts": self.alerts,
            "notes": self.notes,
        }


def analyze_tls_handshake(
    client_stream: Optional[bytes], server_stream: Optional[bytes]
) -> TLSHandshakeInfo:
    info = TLSHandshakeInfo()

    if not client_stream and not server_stream:
        info.notes.append("no TLS bytes observed for this session")
        return info

    client_records = split_tls_records(client_stream or b"")
    server_records = split_tls_records(server_stream or b"")

    client_handshake_stream = extract_handshake_stream(client_records)
    server_handshake_stream = extract_handshake_stream(server_records)

    client_messages = split_handshake_messages(client_handshake_stream)
    server_messages = split_handshake_messages(server_handshake_stream)

    for msg in client_messages:
        if msg["type"] == HANDSHAKE_TYPE_CLIENT_HELLO:
            parsed = parse_client_hello(msg["body"])
            if parsed:
                info.client_hello_seen = True
                info.handshake_observed = True
                info.version_offered = tls_version_name(parsed.get("offered_version"))
                info.cipher_suites_offered = [
                    cipher_info(c)["name"] for c in parsed.get("cipher_suites_offered", [])
                ]
                info.sni = parsed.get("sni")
            break

    for msg in server_messages:
        if msg["type"] == HANDSHAKE_TYPE_SERVER_HELLO:
            parsed = parse_server_hello(msg["body"])
            if parsed:
                info.server_hello_seen = True
                info.handshake_observed = True
                info.version_negotiated = tls_version_name(parsed.get("negotiated_version"))
                selected = parsed.get("cipher_suite_selected")
                if selected is not None:
                    ci = cipher_info(selected)
                    info.cipher_suite_selected = ci["name"]
                    info.key_exchange = ci["key_exchange"]
                    info.forward_secrecy = has_forward_secrecy(ci["key_exchange"])
        elif msg["type"] == HANDSHAKE_TYPE_CERTIFICATE:
            info.handshake_observed = True
            certs = parse_certificate_message(msg["body"])
            info.certificates_der_hex.extend(c.hex() for c in certs)

    if client_handshake_stream and not info.client_hello_seen:
        info.notes.append(
            "handshake-type TLS records observed on the client side but no valid "
            "ClientHello could be parsed (corrupt or truncated)"
        )
    if server_handshake_stream and not info.server_hello_seen:
        info.notes.append(
            "handshake-type TLS records observed on the server side but no valid "
            "ServerHello could be parsed (corrupt or truncated)"
        )

    for alert in extract_alerts(client_records) + extract_alerts(server_records):
        level = "fatal" if alert["level"] == 2 else "warning" if alert["level"] == 1 else "unknown"
        description = alert_description_name(alert["description"])
        info.alerts.append({"level": level, "description": description})
        info.notes.append(f"received {level} TLS alert: {description}")

    return info
