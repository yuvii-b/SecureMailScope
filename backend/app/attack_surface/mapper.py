"""Attack-surface aggregation (Stage 10, "nice-to-have" novelty item).

Rolls the per-session findings/TLS posture already computed for one capture up into a
single "what does this mail infrastructure expose" view: distinct server endpoints, the
protocols/session counts observed per endpoint, each endpoint's worst risk level,
findings-by-severity across the whole capture, and which endpoints are running
deprecated TLS or leaked plaintext after an advertised STARTTLS upgrade.

Pure function of the `session_dicts` list `api/pipeline.py`'s `analyze_pcap_file()`
already builds - no new packet parsing, no DB access - so it's nested directly into the
capture-level `summary` dict with no schema change required.
"""
from __future__ import annotations

_RISK_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_DEPRECATED_TLS_VERSIONS = {"TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"}


def build_attack_surface(session_dicts: list) -> dict:
    endpoints: dict = {}
    protocol_counts: dict = {}
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    deprecated_tls_endpoints = set()
    plaintext_after_starttls_endpoints = set()

    for session in session_dicts:
        server = session["server"]
        key = f"{server['ip']}:{server['port']}"
        protocol = session["protocol"]
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        endpoint = endpoints.setdefault(key, {
            "server_ip": server["ip"],
            "server_port": server["port"],
            "protocols_observed": set(),
            "session_count": 0,
            "worst_risk_level": "LOW",
        })
        endpoint["protocols_observed"].add(protocol)
        endpoint["session_count"] += 1
        session_risk = session.get("risk_level", "LOW")
        if _RISK_RANK.get(session_risk, 0) > _RISK_RANK.get(endpoint["worst_risk_level"], 0):
            endpoint["worst_risk_level"] = session_risk

        version = (session.get("tls_handshake") or {}).get("version_negotiated")
        if version in _DEPRECATED_TLS_VERSIONS:
            deprecated_tls_endpoints.add(key)

        starttls_status = (session.get("starttls_negotiation") or {}).get("status")
        if starttls_status == "PLAINTEXT_AFTER_ADVERTISEMENT":
            plaintext_after_starttls_endpoints.add(key)

        for finding in session.get("findings", []):
            severity = finding["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    endpoint_list = []
    for endpoint in endpoints.values():
        endpoint = dict(endpoint)
        endpoint["protocols_observed"] = sorted(endpoint["protocols_observed"])
        endpoint_list.append(endpoint)
    endpoint_list.sort(
        key=lambda e: (-_RISK_RANK.get(e["worst_risk_level"], 0), e["server_ip"], e["server_port"])
    )

    return {
        "distinct_endpoints": len(endpoints),
        "endpoints": endpoint_list,
        "protocol_counts": protocol_counts,
        "findings_by_severity": severity_counts,
        "endpoints_with_deprecated_tls": sorted(deprecated_tls_endpoints),
        "endpoints_with_plaintext_after_starttls": sorted(plaintext_after_starttls_endpoints),
    }
