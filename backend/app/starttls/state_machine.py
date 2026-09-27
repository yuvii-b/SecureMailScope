"""STARTTLS/STLS state machine (Stage 4).

Classifies, per reassembled session, whether an opportunistic-TLS upgrade succeeded, was
rejected, was never attempted, or was silently downgraded (client/server acked the
upgrade but plaintext protocol traffic continued instead of a TLS handshake -
a STARTTLS-stripping vulnerability). Implicit-TLS sessions (traffic that is TLS from the
very first byte - SMTPS/IMAPS/POP3S ports, or the non-standard-port anomalous scenarios
in genny.py) are reported separately since STARTTLS does not apply to them.

Evidence is pattern-matched against the reassembled plaintext streams from Stage 3 - this
only works for what's actually observable in the capture; when a stream is empty or
ambiguous, the result is NOT_OBSERVED rather than a guess (see CLAUDE.md §12).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

STATUS_SUCCESS = "SUCCESS"
STATUS_REJECTED = "REJECTED"
STATUS_NOT_USED = "NOT_USED"
STATUS_PLAINTEXT_AFTER_ADVERTISEMENT = "PLAINTEXT_AFTER_ADVERTISEMENT"
STATUS_IMPLICIT_TLS = "NOT_APPLICABLE_IMPLICIT_TLS"
STATUS_NOT_OBSERVED = "NOT_OBSERVED"

_COMMAND = {
    "SMTP": re.compile(rb"(?im)^STARTTLS\s*\r?$"),
    "IMAP": re.compile(rb"(?im)^(\S+)\s+STARTTLS\s*\r?$"),
    "POP3": re.compile(rb"(?im)^STLS\s*\r?$"),
}
_ADVERTISED = {
    "SMTP": re.compile(rb"(?i)STARTTLS"),
    "IMAP": re.compile(rb"(?i)STARTTLS"),
    "POP3": re.compile(rb"(?i)STLS"),
}
_NEGATIVE = {
    "SMTP": re.compile(rb"(?im)^5\d\d[ -]"),
    "POP3": re.compile(rb"(?im)^-ERR\b"),
}
_AFFIRMATIVE = {
    "SMTP": re.compile(rb"(?im)^220[ -]"),
    "POP3": re.compile(rb"(?im)^\+OK\b"),
}


@dataclass
class StartTLSResult:
    status: str
    evidence: str
    tls_client_stream: Optional[bytes] = None
    tls_server_stream: Optional[bytes] = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "command_detected": self.status
            not in (STATUS_NOT_USED, STATUS_IMPLICIT_TLS, STATUS_NOT_OBSERVED),
            "evidence": self.evidence,
        }


def _looks_like_tls_record(data: bytes) -> bool:
    return len(data) >= 3 and data[0] in (0x14, 0x15, 0x16, 0x17) and data[1] == 0x03


def _line_at(data: bytes, start: int) -> str:
    end = data.find(b"\n", start)
    end = end + 1 if end != -1 else len(data)
    return data[start:end].decode("ascii", errors="replace").strip()


def _imap_tagged_response(server_to_client: bytes, tag: bytes) -> Optional[re.Match]:
    pattern = re.compile(rb"(?im)^" + re.escape(tag) + rb"\s+(OK|NO|BAD)\b.*$")
    return pattern.search(server_to_client)


def classify(protocol: str, client_to_server: bytes, server_to_client: bytes) -> StartTLSResult:
    if _looks_like_tls_record(client_to_server) or _looks_like_tls_record(server_to_client):
        return StartTLSResult(
            status=STATUS_IMPLICIT_TLS,
            evidence=(
                "TLS record observed as the very first bytes of this session; "
                "no plaintext protocol exchange precedes it"
            ),
            tls_client_stream=client_to_server,
            tls_server_stream=server_to_client,
        )

    if protocol not in _COMMAND:
        return StartTLSResult(
            status=STATUS_NOT_OBSERVED,
            evidence=f"protocol '{protocol}' has no known STARTTLS/STLS command to look for",
        )

    command_match = _COMMAND[protocol].search(client_to_server)

    if command_match is None:
        if _ADVERTISED[protocol].search(server_to_client):
            return StartTLSResult(
                status=STATUS_NOT_USED,
                evidence="server advertised STARTTLS/STLS support but the client never issued the command",
            )
        return StartTLSResult(
            status=STATUS_NOT_OBSERVED,
            evidence="no STARTTLS/STLS command or advertisement observed in this capture",
        )

    tail = client_to_server[command_match.end():].lstrip(b"\r\n")

    if _looks_like_tls_record(tail):
        return StartTLSResult(
            status=STATUS_SUCCESS,
            evidence="TLS record observed immediately after the STARTTLS/STLS command",
            tls_client_stream=tail,
            tls_server_stream=_extract_success_server_tail(protocol, server_to_client),
        )

    if tail:
        return StartTLSResult(
            status=STATUS_PLAINTEXT_AFTER_ADVERTISEMENT,
            evidence=(
                "plaintext protocol traffic continued right after the STARTTLS/STLS "
                f"command instead of a TLS handshake: {tail[:80]!r}"
            ),
        )

    if protocol == "IMAP":
        tag = command_match.group(1)
        reply_match = _imap_tagged_response(server_to_client, tag)
        if reply_match is None:
            return StartTLSResult(
                status=STATUS_NOT_OBSERVED,
                evidence="STARTTLS command sent but no correlated server response observed",
            )
        reply_text = reply_match.group(0).decode("ascii", errors="replace").strip()
        verb = reply_match.group(1).upper()
        if verb in (b"NO", b"BAD"):
            return StartTLSResult(status=STATUS_REJECTED, evidence=reply_text)
        server_tail = server_to_client[reply_match.end():].lstrip(b"\r\n")
        return StartTLSResult(
            status=STATUS_SUCCESS,
            evidence=reply_text,
            tls_server_stream=server_tail if _looks_like_tls_record(server_tail) else None,
        )

    negative_re = _NEGATIVE[protocol]
    neg_matches = list(negative_re.finditer(server_to_client))
    if neg_matches:
        m = neg_matches[-1]
        return StartTLSResult(status=STATUS_REJECTED, evidence=_line_at(server_to_client, m.start()))

    affirmative_re = _AFFIRMATIVE[protocol]
    aff_matches = list(affirmative_re.finditer(server_to_client))
    if aff_matches:
        m = aff_matches[-1]
        server_tail = server_to_client[m.end():].lstrip(b"\r\n")
        return StartTLSResult(
            status=STATUS_SUCCESS,
            evidence=_line_at(server_to_client, m.start()),
            tls_server_stream=server_tail if _looks_like_tls_record(server_tail) else None,
        )

    return StartTLSResult(
        status=STATUS_NOT_OBSERVED,
        evidence="STARTTLS/STLS command sent but no correlated server response observed",
    )


def _extract_success_server_tail(protocol: str, server_to_client: bytes) -> Optional[bytes]:
    """Best-effort slice of the server's TLS bytes for a SUCCESS session (SMTP/POP3 path).

    The server's plaintext "ready to start TLS" reply is followed, later in the same
    direction's byte stream, by its ServerHello etc. We don't have a tag to correlate on
    for SMTP/POP3, so fall back to locating the first TLS record header anywhere in the
    stream after the last affirmative reply line.
    """
    affirmative_re = _AFFIRMATIVE.get(protocol)
    search_from = 0
    if affirmative_re:
        matches = list(affirmative_re.finditer(server_to_client))
        if matches:
            search_from = matches[-1].end()
    for offset in range(search_from, max(len(server_to_client) - 3, search_from)):
        if _looks_like_tls_record(server_to_client[offset:]):
            return server_to_client[offset:]
    return None
