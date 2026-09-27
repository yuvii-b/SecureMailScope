from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from ..certificates.analyzer import analyze_certificate_chain
from ..ingestion.validator import PcapValidationError, validate_pcap_file
from ..starttls.state_machine import classify as classify_starttls
from ..tls.handshake import analyze_tls_handshake
from .reassembler import reassemble_pcap

router = APIRouter(prefix="/api/pcap", tags=["reassembly"])

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


@router.post("/sessions")
async def reassemble_sessions(file: UploadFile = File(...)) -> dict:
    suffix = Path(file.filename or "capture.pcap").suffix or ".pcap"

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        size = 0

        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="Capture exceeds 200MB limit")
            tmp.write(chunk)

    try:
        validate_pcap_file(tmp_path)
        sessions = reassemble_pcap(tmp_path)
    except PcapValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    session_dicts = []
    for session in sessions:
        starttls_result = classify_starttls(
            session.protocol, session.client_to_server.data, session.server_to_client.data
        )
        tls_info = analyze_tls_handshake(
            starttls_result.tls_client_stream, starttls_result.tls_server_stream
        )
        evaluation_time = (
            datetime.fromtimestamp(session.capture_time, tz=timezone.utc)
            if session.capture_time is not None
            else None
        )
        certificate_analysis = analyze_certificate_chain(
            tls_info.certificates_der_hex,
            evaluation_time=evaluation_time,
            hostname=tls_info.sni,
        )
        session_dict = session.to_dict()
        session_dict["starttls"] = starttls_result.to_dict()
        session_dict["tls_handshake"] = tls_info.to_dict()
        session_dict["certificate"] = certificate_analysis.to_dict()
        session_dicts.append(session_dict)

    return {
        "filename": file.filename,
        "session_count": len(sessions),
        "sessions": session_dicts,
    }
