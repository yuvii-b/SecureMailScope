from app.attack_surface.mapper import build_attack_surface


def _session(protocol, ip, port, risk_level, findings=None, tls_version=None, starttls_status=None):
    return {
        "server": {"ip": ip, "port": port},
        "protocol": protocol,
        "risk_level": risk_level,
        "findings": findings or [],
        "tls_handshake": {"version_negotiated": tls_version},
        "starttls_negotiation": {"status": starttls_status},
    }


def test_empty_capture_has_no_endpoints():
    surface = build_attack_surface([])
    assert surface["distinct_endpoints"] == 0
    assert surface["endpoints"] == []
    assert surface["findings_by_severity"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}


def test_distinct_endpoints_counted_by_ip_and_port():
    sessions = [
        _session("SMTP", "10.0.0.1", 25, "LOW"),
        _session("SMTP", "10.0.0.1", 25, "LOW"),
        _session("POP3", "10.0.0.2", 110, "LOW"),
    ]
    surface = build_attack_surface(sessions)
    assert surface["distinct_endpoints"] == 2
    endpoint = next(e for e in surface["endpoints"] if e["server_ip"] == "10.0.0.1")
    assert endpoint["session_count"] == 2
    assert endpoint["protocols_observed"] == ["SMTP"]


def test_worst_risk_level_tracked_per_endpoint():
    sessions = [
        _session("SMTP", "10.0.0.1", 25, "LOW"),
        _session("SMTP", "10.0.0.1", 25, "CRITICAL"),
    ]
    surface = build_attack_surface(sessions)
    assert surface["endpoints"][0]["worst_risk_level"] == "CRITICAL"


def test_endpoints_sorted_worst_risk_first():
    sessions = [
        _session("SMTP", "10.0.0.1", 25, "LOW"),
        _session("SMTP", "10.0.0.2", 25, "CRITICAL"),
        _session("SMTP", "10.0.0.3", 25, "MEDIUM"),
    ]
    surface = build_attack_surface(sessions)
    ordered_ips = [e["server_ip"] for e in surface["endpoints"]]
    assert ordered_ips == ["10.0.0.2", "10.0.0.3", "10.0.0.1"]


def test_findings_by_severity_aggregated_across_sessions():
    sessions = [
        _session("SMTP", "10.0.0.1", 25, "CRITICAL", findings=[{"severity": "CRITICAL"}, {"severity": "HIGH"}]),
        _session("SMTP", "10.0.0.2", 25, "LOW", findings=[{"severity": "HIGH"}]),
    ]
    surface = build_attack_surface(sessions)
    assert surface["findings_by_severity"]["CRITICAL"] == 1
    assert surface["findings_by_severity"]["HIGH"] == 2


def test_deprecated_tls_and_plaintext_after_starttls_endpoints_flagged():
    sessions = [
        _session("SMTP", "10.0.0.1", 25, "HIGH", tls_version="TLS 1.0"),
        _session("IMAP", "10.0.0.2", 143, "CRITICAL", starttls_status="PLAINTEXT_AFTER_ADVERTISEMENT"),
        _session("SMTP", "10.0.0.3", 25, "LOW", tls_version="TLS 1.3"),
    ]
    surface = build_attack_surface(sessions)
    assert surface["endpoints_with_deprecated_tls"] == ["10.0.0.1:25"]
    assert surface["endpoints_with_plaintext_after_starttls"] == ["10.0.0.2:143"]
