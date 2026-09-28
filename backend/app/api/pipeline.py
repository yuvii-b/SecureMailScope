"""Shared analysis pipeline producing the §7 JSON contract shape (Stage 7).

Both the synchronous debug endpoint (`reassembly/router.py`, Stages 3-6) and this stage's
async Celery task call the per-session stages directly; this module is the one place that
wires reassembly -> STARTTLS -> TLS handshake -> certificate -> rule engine into a single
session dict and aggregates a capture-level summary, so the contract shape is defined once.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..attack_surface.mapper import build_attack_surface
from ..certificates.analyzer import analyze_certificate_chain
from ..fingerprint.fingerprint import compute_fingerprint
from ..ml.inference import analyze as analyze_ml
from ..reassembly.reassembler import reassemble_pcap
from ..rules.engine import evaluate_session
from ..starttls.state_machine import classify as classify_starttls
from ..tls.handshake import analyze_tls_handshake

SCHEMA_VERSION = "1.0"

# The overall risk level is never better than the worst session's - one badly
# misconfigured endpoint is enough to compromise mail flow through it.
_RISK_LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def analyze_session(session) -> dict:
    """Runs STARTTLS -> TLS handshake -> certificate -> rule engine for one session."""
    starttls_result = classify_starttls(
        session.protocol, session.client_to_server.data, session.server_to_client.data
    )
    tls_info = analyze_tls_handshake(starttls_result.tls_client_stream, starttls_result.tls_server_stream)
    evaluation_time = (
        datetime.fromtimestamp(session.capture_time, tz=timezone.utc)
        if session.capture_time is not None
        else None
    )
    certificate_analysis = analyze_certificate_chain(
        tls_info.certificates_der_hex, evaluation_time=evaluation_time, hostname=tls_info.sni
    )
    starttls_dict = starttls_result.to_dict()
    tls_dict = tls_info.to_dict()
    certificate_dict = certificate_analysis.to_dict()
    rule_result = evaluate_session(tls_dict, certificate_dict, starttls_dict)
    # Stage 9: purely additive - falls back to None if the models haven't been trained
    # yet, so the rule engine above keeps working standalone either way (CLAUDE.md §12).
    ai_analysis = analyze_ml(session, tls_dict, certificate_dict, starttls_dict)
    # Stage 10: also purely additive and DB-free - combines this session's crypto posture
    # into one comparable ID; drift detection (worker.py) uses it as a cheap pre-check.
    crypto_fingerprint = compute_fingerprint(tls_dict, certificate_dict).to_dict()

    return {
        "starttls": starttls_dict,
        "tls_handshake": tls_dict,
        "certificate": certificate_dict,
        "findings": [f.to_dict() for f in rule_result.findings],
        "posture_score": rule_result.posture_score,
        "risk_level": rule_result.risk_level,
        "ai_analysis": ai_analysis,
        "crypto_fingerprint": crypto_fingerprint,
    }


def _overall_risk_level(risk_levels: list[str]) -> str:
    if not risk_levels:
        return "LOW"
    return max(risk_levels, key=lambda level: _RISK_LEVEL_RANK.get(level, 0))


def analyze_pcap_file(path: Path, filename: str) -> dict:
    """Runs the full pipeline and returns the frozen §7 contract dict for one capture."""
    sessions = reassemble_pcap(path)

    session_dicts = []
    posture_scores = []
    risk_levels = []
    for i, session in enumerate(sessions, start=1):
        analysis = analyze_session(session)
        posture_scores.append(analysis["posture_score"])
        risk_levels.append(analysis["risk_level"])
        session_dicts.append({
            "session_id": f"SESS-{session.protocol}-{i}",
            "protocol": session.protocol,
            "client": {"ip": session.client[0], "port": session.client[1]},
            "server": {"ip": session.server[0], "port": session.server[1]},
            "starttls_negotiation": analysis["starttls"],
            "tls_handshake": analysis["tls_handshake"],
            "certificate": analysis["certificate"],
            "ai_analysis": analysis["ai_analysis"],
            "crypto_fingerprint": analysis["crypto_fingerprint"],
            "findings": analysis["findings"],
            "posture_score": analysis["posture_score"],
            "risk_level": analysis["risk_level"],
        })

    overall_health_score = (
        round(sum(posture_scores) / len(posture_scores), 1) if posture_scores else 100.0
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "summary": {
            "capture_file": filename,
            "total_sessions_analyzed": len(sessions),
            "overall_health_score": overall_health_score,
            "risk_level": _overall_risk_level(risk_levels),
            # Stage 10: purely additive, aggregated from session_dicts already built
            # above - no new parsing, no DB access (CLAUDE.md §10's attack-surface item).
            "attack_surface": build_attack_surface(session_dicts),
        },
        "sessions": session_dicts,
    }
