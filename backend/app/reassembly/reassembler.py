"""TCP stream reassembly (Stage 3).

Builds on Stage 2's flow grouping but goes one level deeper: within each flow, packets
are split by direction, each direction's segments are ordered by TCP sequence number
(not capture order - see genny.py's `18_tcp_out_of_order.pcap`, where packets are
emitted out of causal order but still carry monotonic per-direction sequence numbers),
exact retransmissions are deduplicated, and any sequence gaps are recorded rather than
silently dropped.

Client/server direction is resolved from the initial SYN (the SYN-without-ACK packet
always originates from the client, in genny.py's synthetic handshakes and in real TCP)
rather than from port number, since two of genny.py's anomalous scenarios run SMTP-like
traffic on non-standard ports 2525/2526.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ..ingestion.extractor import _flow_key
from ..ingestion.validator import PcapValidationError
from .protocol_id import identify_protocol

_SYN, _ACK = 0x02, 0x10
_SERVER_PORT_HINTS = {25, 587, 465, 143, 993, 110, 995}


@dataclass
class Gap:
    after_seq: int
    missing_bytes: int

    def to_dict(self) -> dict:
        return {"after_seq": self.after_seq, "missing_bytes": self.missing_bytes}


@dataclass
class ReassembledStream:
    data: bytes = b""
    gaps: list = field(default_factory=list)
    retransmitted_segments: int = 0
    out_of_order_segments: int = 0

    def to_dict(self) -> dict:
        return {
            "byte_count": len(self.data),
            "gaps": [g.to_dict() for g in self.gaps],
            "retransmitted_segments": self.retransmitted_segments,
            "out_of_order_segments": self.out_of_order_segments,
        }


@dataclass
class ReassembledSession:
    transport: str
    client: tuple
    server: tuple
    client_to_server: ReassembledStream
    server_to_client: ReassembledStream
    protocol: str
    protocol_confidence: str
    protocol_evidence: str
    capture_time: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "transport": self.transport,
            "client": {"ip": self.client[0], "port": self.client[1]},
            "server": {"ip": self.server[0], "port": self.server[1]},
            "protocol": self.protocol,
            "protocol_confidence": self.protocol_confidence,
            "protocol_evidence": self.protocol_evidence,
            "client_to_server": self.client_to_server.to_dict(),
            "server_to_client": self.server_to_client.to_dict(),
        }


def _reassemble_direction(segments: list) -> ReassembledStream:
    """segments: list of (arrival_index, seq, payload) captured for one direction."""
    stream = ReassembledStream()
    if not segments:
        return stream

    by_seq = sorted(segments, key=lambda s: s[1])

    arrival_order = [s[0] for s in segments]
    sorted_order = [s[0] for s in by_seq]
    if arrival_order != sorted_order:
        stream.out_of_order_segments = sum(
            1 for a, b in zip(arrival_order, sorted_order) if a != b
        )

    expected_seq: Optional[int] = None
    chunks = []

    for _, seq, payload in by_seq:
        if expected_seq is not None:
            if seq < expected_seq:
                covered_end = seq + len(payload)
                if covered_end <= expected_seq:
                    # Fully covered by data already appended - exact or partial retransmission.
                    stream.retransmitted_segments += 1
                    continue
                # Partial overlap: keep only the previously-unseen tail.
                payload = payload[expected_seq - seq :]
                seq = expected_seq
            elif seq > expected_seq:
                stream.gaps.append(Gap(after_seq=expected_seq, missing_bytes=seq - expected_seq))

        chunks.append(payload)
        expected_seq = seq + len(payload)

    stream.data = b"".join(chunks)
    return stream


def _find_client_endpoint(packets) -> Optional[tuple]:
    for pkt in packets:
        tcp = pkt[TCP]
        if tcp.flags & _SYN and not tcp.flags & _ACK:
            return (pkt[IP].src, int(tcp.sport))
    return None


def _resolve_endpoints(ep_a: tuple, ep_b: tuple) -> tuple:
    """Fallback used only when no SYN packet was captured. Returns (client, server)."""
    a_known = ep_a[1] in _SERVER_PORT_HINTS
    b_known = ep_b[1] in _SERVER_PORT_HINTS
    if a_known and not b_known:
        return ep_b, ep_a
    if b_known and not a_known:
        return ep_a, ep_b
    return (ep_a, ep_b) if ep_a[1] > ep_b[1] else (ep_b, ep_a)


def reassemble_pcap(path: Path) -> list:
    try:
        packets = rdpcap(str(path))
    except Exception as exc:  # Scapy raises varied exception types on truncated/corrupt captures
        raise PcapValidationError(f"Could not parse capture: {exc}") from exc

    flows: dict = {}

    for idx, pkt in enumerate(packets):
        if IP not in pkt or TCP not in pkt:
            continue

        ip_layer = pkt[IP]
        tcp = pkt[TCP]
        key = _flow_key(ip_layer.src, int(tcp.sport), ip_layer.dst, int(tcp.dport), "TCP")
        flows.setdefault(key, []).append((idx, pkt))

    sessions = []

    for key, indexed_packets in flows.items():
        raw_packets = [p for _, p in indexed_packets]

        client_endpoint = _find_client_endpoint(raw_packets)
        if client_endpoint is None:
            client_endpoint, server_endpoint = _resolve_endpoints(key[1], key[2])
        else:
            server_endpoint = key[2] if client_endpoint == key[1] else key[1]

        c2s, s2c = [], []

        for idx, pkt in indexed_packets:
            if not pkt.haslayer(Raw):
                continue
            payload = bytes(pkt[Raw].load)
            if not payload:
                continue

            tcp = pkt[TCP]
            src = (pkt[IP].src, int(tcp.sport))
            entry = (idx, int(tcp.seq), payload)

            (c2s if src == client_endpoint else s2c).append(entry)

        client_to_server = _reassemble_direction(c2s)
        server_to_client = _reassemble_direction(s2c)

        proto = identify_protocol(server_endpoint[1], server_to_client.data)

        capture_time = min((float(p.time) for p in raw_packets), default=None)

        sessions.append(
            ReassembledSession(
                transport="TCP",
                client=client_endpoint,
                server=server_endpoint,
                client_to_server=client_to_server,
                server_to_client=server_to_client,
                protocol=proto["protocol"],
                protocol_confidence=proto["confidence"],
                protocol_evidence=proto["evidence"],
                capture_time=capture_time,
            )
        )

    sessions.sort(key=lambda s: (s.client, s.server))
    return sessions
