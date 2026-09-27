"""SMTP/IMAP/POP3 protocol identification (Stage 3).

Port number alone is a weak signal here: STARTTLS traffic runs on the well-known ports,
but two of genny.py's anomalous scenarios (`19_malformed_tls.pcap`, `21_unusual_cipher...`)
run SMTP-like traffic on non-standard ports 2525/2526. The banner the server sends right
after the TCP handshake is the authoritative signal, so it is checked first; the port is
only a fallback when no recognizable plaintext banner was captured (e.g. implicit-TLS
scenarios where the stream is TLS from the first byte).
"""
from __future__ import annotations

import re

_BANNER_PATTERNS = (
    ("SMTP", re.compile(rb"^220[ -]")),
    ("IMAP", re.compile(rb"^\*\s+OK\b", re.IGNORECASE)),
    ("POP3", re.compile(rb"^\+OK\b")),
)

_PORT_HINTS = {
    25: "SMTP",
    587: "SMTP",
    465: "SMTPS",
    143: "IMAP",
    993: "IMAPS",
    110: "POP3",
    995: "POP3S",
}


def identify_protocol(server_port: int, server_to_client: bytes) -> dict:
    banner = server_to_client[:64]

    for protocol, pattern in _BANNER_PATTERNS:
        if pattern.match(banner):
            return {
                "protocol": protocol,
                "confidence": "banner_match",
                "evidence": banner.decode("ascii", errors="replace").strip(),
            }

    port_guess = _PORT_HINTS.get(server_port)
    if port_guess:
        return {
            "protocol": port_guess,
            "confidence": "port_heuristic",
            "evidence": f"no recognizable plaintext banner; guessed from server port {server_port}",
        }

    return {
        "protocol": "UNKNOWN",
        "confidence": "none",
        "evidence": f"no recognizable banner and no known protocol mapping for port {server_port}",
    }
