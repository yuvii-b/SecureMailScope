"""Async analysis endpoints implementing the §7 JSON contract (Stage 7).

This is additive to `reassembly/router.py`'s existing `/api/pcap/sessions` (Stages 3-6),
which stays as a synchronous, no-persistence debug endpoint for quick sanity checks. These
routes are the "real" pipeline entry point: upload enqueues a Celery job and persists the
result to PostgreSQL (SQLite locally - see app/db.py) instead of returning it transiently.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session as DBSession

from ..db import get_db
from ..ingestion.validator import PcapValidationError, validate_pcap_file
from ..models.analysis import Capture, SessionRecord
from ..worker import UPLOAD_DIR, analyze_pcap_task
from .contract import build_contract

router = APIRouter(prefix="/api/analyses", tags=["analyses"])

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


@router.post("", status_code=202)
async def create_analysis(file: UploadFile = File(...), db: DBSession = Depends(get_db)) -> dict:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
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
    except PcapValidationError as exc:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    capture = Capture(filename=file.filename or "capture.pcap")
    db.add(capture)
    db.commit()
    db.refresh(capture)

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / f"{capture.id}.pcap"
    tmp_path.replace(dest)

    analyze_pcap_task.delay(capture.id)
    db.refresh(capture)  # picks up the status the (possibly-eager) task just wrote
    return {"capture_id": capture.id, "status": capture.status}


@router.get("")
def list_analyses(db: DBSession = Depends(get_db)) -> dict:
    captures = db.query(Capture).order_by(Capture.created_at.desc()).all()
    return {"analyses": [c.to_dict() for c in captures]}


@router.get("/{capture_id}")
def get_analysis(capture_id: str, db: DBSession = Depends(get_db)) -> dict:
    capture = db.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(status_code=404, detail=f"No analysis found for capture_id={capture_id}")

    if capture.status != "COMPLETE":
        return capture.to_dict()

    sessions = (
        db.query(SessionRecord)
        .filter(SessionRecord.capture_id == capture_id)
        .order_by(SessionRecord.id)
        .all()
    )
    return build_contract(capture, sessions)
