"""What-if remediation simulator endpoints (Stage 10).

Mounted at its own `/api/simulator` prefix rather than nested under `/api/analyses/{id}`
so its `/remediations` catalog route can't collide with `GET /api/analyses/{capture_id}`
(FastAPI would otherwise try to match "remediations" as a capture_id path segment).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session as DBSession

from ..db import get_db
from ..models.analysis import SessionRecord
from .remediation import list_remediations, simulate_remediation

router = APIRouter(prefix="/api/simulator", tags=["simulator"])


class SimulateRequest(BaseModel):
    remediations: list[str]


@router.get("/remediations")
def get_remediation_catalog() -> dict:
    return {"remediations": list_remediations()}


@router.post("/{capture_id}/sessions/{session_id}")
def simulate_session_remediation(
    capture_id: str, session_id: str, body: SimulateRequest, db: DBSession = Depends(get_db)
) -> dict:
    session = (
        db.query(SessionRecord)
        .filter(SessionRecord.capture_id == capture_id, SessionRecord.session_id == session_id)
        .first()
    )
    if session is None:
        raise HTTPException(
            status_code=404, detail=f"No session {session_id} found for capture_id={capture_id}"
        )
    if not body.remediations:
        raise HTTPException(status_code=422, detail="Provide at least one remediation id in 'remediations'")

    try:
        return simulate_remediation(session.tls_handshake, session.certificate, session.starttls, body.remediations)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
