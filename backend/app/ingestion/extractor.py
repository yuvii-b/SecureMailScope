"""Packet reading and 5-tuple flow extraction (Stage 2).

Deliberately stops short of protocol identification (SMTP/IMAP/POP3 banners) and TCP
stream reassembly (sequence tracking, out-of-order handling) - those belong to Stage 3.
This module's only job: read every packet in the capture and group them into
direction-agnostic flows so later stages have something to iterate over.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP

from .validator import PcapValidationError


@dataclass
class Flow:
    transport: str
    endpoint_a: tuple
    endpoint_b: tuple
    packet_count: int = 0
    byte_count: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    def observe(self, pkt_len: int, ts: float) -> None:
        self.packet_count += 1
        self.byte_count += pkt_len
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)

    def to_dict(self) -> dict:
        return {
            "transport": self.transport,
            "endpoints": [
                {"ip": self.endpoint_a[0], "port": self.endpoint_a[1]},
                {"ip": self.endpoint_b[0], "port": self.endpoint_b[1]},
            ],
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": (
                round(self.last_seen - self.first_seen, 6)
                if self.first_seen is not None and self.last_seen is not None
                else None
            ),
        }


@dataclass
class ExtractionResult:
    total_packets: int
    parsed_packets: int
    non_ip_packets: int
    flows: list

    def to_dict(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "parsed_packets": self.parsed_packets,
            "non_ip_packets": self.non_ip_packets,
            "flow_count": len(self.flows),
            "flows": [f.to_dict() for f in self.flows],
        }


def _flow_key(src_ip: str, sport: int, dst_ip: str, dport: int, transport: str) -> tuple:
    """Direction-agnostic key so both halves of a connection merge into one flow."""
    a = (src_ip, sport)
    b = (dst_ip, dport)
    return (transport,) + tuple(sorted([a, b]))


def extract_flows(path: Path) -> ExtractionResult:
    try:
        packets = rdpcap(str(path))
    except Exception as exc:  # Scapy raises varied exception types on truncated/corrupt captures
        raise PcapValidationError(f"Could not parse capture: {exc}") from exc

    flows: dict[tuple, Flow] = {}
    non_ip_packets = 0

    for pkt in packets:
        if IP not in pkt:
            non_ip_packets += 1
            continue

        ip_layer = pkt[IP]

        if TCP in pkt:
            transport = "TCP"
            sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        elif UDP in pkt:
            transport = "UDP"
            sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
        else:
            non_ip_packets += 1
            continue

        key = _flow_key(ip_layer.src, sport, ip_layer.dst, dport, transport)
        flow = flows.get(key)

        if flow is None:
            _, ep_a, ep_b = key[0], key[1], key[2]
            flow = Flow(transport=key[0], endpoint_a=key[1], endpoint_b=key[2])
            flows[key] = flow

        flow.observe(len(pkt), float(pkt.time))

    ordered_flows = sorted(flows.values(), key=lambda f: f.first_seen or 0.0)

    return ExtractionResult(
        total_packets=len(packets),
        parsed_packets=len(packets) - non_ip_packets,
        non_ip_packets=non_ip_packets,
        flows=ordered_flows,
    )
