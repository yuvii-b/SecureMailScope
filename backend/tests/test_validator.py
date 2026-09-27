import pytest

from app.ingestion.validator import PcapValidationError, validate_pcap_bytes


def test_valid_pcap_magic_le():
    result = validate_pcap_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    assert result.file_format == "pcap"


def test_valid_pcap_magic_be():
    result = validate_pcap_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 20)
    assert result.file_format == "pcap"


def test_valid_pcapng_magic():
    result = validate_pcap_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
    assert result.file_format == "pcapng"


def test_rejects_unknown_signature():
    with pytest.raises(PcapValidationError):
        validate_pcap_bytes(b"NOTAPCAP" * 4)


def test_rejects_too_small_file():
    with pytest.raises(PcapValidationError):
        validate_pcap_bytes(b"\x00\x01")
