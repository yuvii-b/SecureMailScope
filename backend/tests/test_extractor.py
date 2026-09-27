from app.ingestion.extractor import extract_flows
from app.ingestion.validator import validate_pcap_file


def test_single_smtp_session_is_one_flow(dataset_dir):
    pcap = dataset_dir / "03_tls12_ecdhe_rsa_safe.pcap"

    validation = validate_pcap_file(pcap)
    assert validation.file_format == "pcap"

    result = extract_flows(pcap)
    assert result.total_packets > 0
    assert len(result.flows) == 1
    assert result.flows[0].transport == "TCP"


def test_combined_pcap_has_three_flows(dataset_dir):
    # genny.py's file 22 stitches three independent SMTP/POP3 sessions into one capture.
    pcap = dataset_dir / "22_multiple_sessions_combined.pcap"

    result = extract_flows(pcap)
    assert len(result.flows) == 3


def test_segmented_tls_handshake_still_one_flow(dataset_dir):
    # TCP segmentation must not fragment a single connection into multiple flows.
    pcap = dataset_dir / "16_tcp_segmented_tls_handshake.pcap"

    result = extract_flows(pcap)
    assert len(result.flows) == 1
    assert result.flows[0].packet_count > 5


def test_out_of_order_packets_still_one_flow(dataset_dir):
    pcap = dataset_dir / "18_tcp_out_of_order.pcap"

    result = extract_flows(pcap)
    assert len(result.flows) == 1
