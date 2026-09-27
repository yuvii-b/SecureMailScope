"""PCAP/PCAPNG file validation: magic-byte identification and size sanity checks.

This module does not parse packets - see extractor.py for that. Its only job is to
reject anything that isn't a plausible capture file before we hand it to Scapy.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"
PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

KNOWN_MAGICS = {
    PCAP_MAGIC_BE: "pcap",
    PCAP_MAGIC_LE: "pcap",
    PCAP_MAGIC_NS_BE: "pcap-ns",
    PCAP_MAGIC_NS_LE: "pcap-ns",
    PCAPNG_MAGIC: "pcapng",
}


class PcapValidationError(ValueError):
    """Raised when an uploaded file is not a usable PCAP/PCAPNG capture."""


@dataclass
class ValidationResult:
    file_format: str
    size_bytes: int


def validate_pcap_bytes(data: bytes) -> ValidationResult:
    if len(data) < 4:
        raise PcapValidationError("File is too small to be a valid capture")

    magic = data[:4]
    file_format = KNOWN_MAGICS.get(magic)

    if file_format is None:
        raise PcapValidationError(
            f"Unrecognized file signature 0x{magic.hex()}; expected a pcap or pcapng capture"
        )

    return ValidationResult(file_format=file_format, size_bytes=len(data))


def validate_pcap_file(path: Path) -> ValidationResult:
    size = path.stat().st_size

    with open(path, "rb") as f:
        header = f.read(4)

    if len(header) < 4:
        raise PcapValidationError("File is too small to be a valid capture")

    file_format = KNOWN_MAGICS.get(header)

    if file_format is None:
        raise PcapValidationError(
            f"Unrecognized file signature 0x{header.hex()}; expected a pcap or pcapng capture"
        )

    return ValidationResult(file_format=file_format, size_bytes=size)
