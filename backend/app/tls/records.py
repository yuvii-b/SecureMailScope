"""TLS record and handshake-message framing (Stage 4).

Pure byte-layout parsing, no interpretation of the parsed fields - see `handshake.py` for
that. Truncated or malformed input stops parsing early and returns whatever was
successfully framed, rather than raising or guessing (CLAUDE.md §12): genny.py's
`malformed_tls()` scenario (files `19`/`21`) deliberately declares handshake-message
lengths far larger than the bytes actually present.
"""
from __future__ import annotations

CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14
CONTENT_TYPE_ALERT = 0x15
CONTENT_TYPE_HANDSHAKE = 0x16
CONTENT_TYPE_APPLICATION_DATA = 0x17


def split_tls_records(data: bytes) -> list[dict]:
    records = []
    offset = 0
    while offset + 5 <= len(data):
        content_type = data[offset]
        version = int.from_bytes(data[offset + 1:offset + 3], "big")
        length = int.from_bytes(data[offset + 3:offset + 5], "big")
        payload_start = offset + 5
        payload_end = payload_start + length
        if payload_end > len(data):
            break
        records.append(
            {"content_type": content_type, "version": version, "payload": data[payload_start:payload_end]}
        )
        offset = payload_end
    return records


def split_handshake_messages(handshake_stream: bytes) -> list[dict]:
    messages = []
    offset = 0
    while offset + 4 <= len(handshake_stream):
        msg_type = handshake_stream[offset]
        length = int.from_bytes(handshake_stream[offset + 1:offset + 4], "big")
        body_start = offset + 4
        body_end = body_start + length
        if body_end > len(handshake_stream):
            break
        messages.append({"type": msg_type, "body": handshake_stream[body_start:body_end]})
        offset = body_end
    return messages


def extract_handshake_stream(records: list[dict]) -> bytes:
    return b"".join(r["payload"] for r in records if r["content_type"] == CONTENT_TYPE_HANDSHAKE)


def extract_alerts(records: list[dict]) -> list[dict]:
    alerts = []
    for r in records:
        if r["content_type"] == CONTENT_TYPE_ALERT and len(r["payload"]) >= 2:
            alerts.append({"level": r["payload"][0], "description": r["payload"][1]})
    return alerts
