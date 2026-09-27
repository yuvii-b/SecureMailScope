from app.reassembly.reassembler import reassemble_pcap


def test_simple_smtp_session_identified_and_reassembled(dataset_dir):
    pcap = dataset_dir / "03_tls12_ecdhe_rsa_safe.pcap"

    sessions = reassemble_pcap(pcap)
    assert len(sessions) == 1

    session = sessions[0]
    assert session.server[1] == 25
    assert session.protocol == "SMTP"
    assert session.protocol_confidence == "banner_match"
    assert b"220 mail.example.test ESMTP SecureMailScope" in session.server_to_client.data
    assert b"STARTTLS" in session.client_to_server.data
    assert session.server_to_client.gaps == []
    assert session.client_to_server.gaps == []


def test_imap_starttls_rejected_identified(dataset_dir):
    pcap = dataset_dir / "14_starttls_rejected.pcap"

    sessions = reassemble_pcap(pcap)
    assert len(sessions) == 1

    session = sessions[0]
    assert session.server[1] == 143
    assert session.protocol == "IMAP"
    assert b"NO STARTTLS unavailable" in session.server_to_client.data


def test_pop3_plaintext_credentials_visible(dataset_dir):
    pcap = dataset_dir / "15_pop3_plaintext_credentials.pcap"

    sessions = reassemble_pcap(pcap)
    assert len(sessions) == 1

    session = sessions[0]
    assert session.protocol == "POP3"
    # Passive analyzer must be able to see this in plaintext - that's the finding.
    assert b"PASS SuperSecretPassword123!" in session.client_to_server.data


def test_segmented_handshake_reassembles_to_contiguous_stream(dataset_dir):
    pcap = dataset_dir / "16_tcp_segmented_tls_handshake.pcap"

    sessions = reassemble_pcap(pcap)
    session = sessions[0]

    # Segmentation must not fragment the stream or lose bytes.
    assert session.server_to_client.gaps == []
    assert session.server_to_client.out_of_order_segments == 0
    assert len(session.server_to_client.data) > 200  # includes the embedded certificate


def test_retransmission_is_deduplicated(dataset_dir):
    pcap = dataset_dir / "17_tcp_retransmission.pcap"

    sessions = reassemble_pcap(pcap)
    session = sessions[0]

    total_retransmissions = (
        session.client_to_server.retransmitted_segments
        + session.server_to_client.retransmitted_segments
    )
    assert total_retransmissions > 0
    # Deduplicated stream must still be gap-free and contain no duplicated bytes.
    assert session.client_to_server.gaps == []
    assert session.server_to_client.gaps == []


def test_out_of_order_packets_reordered_by_sequence_number(dataset_dir):
    pcap = dataset_dir / "18_tcp_out_of_order.pcap"

    sessions = reassemble_pcap(pcap)
    session = sessions[0]

    assert session.client_to_server.gaps == []
    assert session.server_to_client.gaps == []
    assert b"STARTTLS" in session.client_to_server.data


def test_nonstandard_port_smtp_like_traffic_is_unknown_protocol(dataset_dir):
    pcap = dataset_dir / "19_malformed_tls.pcap"

    sessions = reassemble_pcap(pcap)
    session = sessions[0]

    assert session.server[1] == 2525
    assert session.protocol == "UNKNOWN"
    assert session.protocol_confidence == "none"


def test_multiple_sessions_each_identified_independently(dataset_dir):
    pcap = dataset_dir / "22_multiple_sessions_combined.pcap"

    sessions = reassemble_pcap(pcap)
    assert len(sessions) == 3

    protocols = sorted(s.protocol for s in sessions)
    assert protocols == ["POP3", "SMTP", "SMTP"]
