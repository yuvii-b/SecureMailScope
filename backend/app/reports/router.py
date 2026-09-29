"""Report export endpoints (Stage 11): JSON, HTML, and PDF views of a completed capture.

Mounted under the existing `/api/analyses` prefix as `/{capture_id}/report.<ext>` -
additive routes alongside `api/router.py`'s `GET /api/analyses/{capture_id}` (which stays
the live-dashboard/debug JSON view), all reading through the one shared
`api.contract.build_contract()` helper so a report can never show something different
from what the dashboard shows for the same capture.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy.orm import Session as DBSession

from ..api.contract import build_contract
from ..db import get_db
from ..models.analysis import Capture, SessionRecord
from .renderer import render_html, render_pdf

router = APIRouter(prefix="/api/analyses", tags=["reports"])


def _load_report_data(capture_id: str, db: DBSession) -> dict:
    capture = db.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(status_code=404, detail=f"No analysis found for capture_id={capture_id}")
    if capture.status != "COMPLETE":
        raise HTTPException(
            status_code=409,
            detail=f"Analysis {capture_id} is not COMPLETE yet (status={capture.status}) - no report to export",
        )

    sessions = (
        db.query(SessionRecord)
        .filter(SessionRecord.capture_id == capture_id)
        .order_by(SessionRecord.id)
        .all()
    )
    contract = build_contract(capture, sessions)
    return {
        **contract,
        "completed_at": capture.completed_at.isoformat() if capture.completed_at else None,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


@router.get("/{capture_id}/report.json")
def get_report_json(capture_id: str, db: DBSession = Depends(get_db)) -> JSONResponse:
    report_data = _load_report_data(capture_id, db)
    filename = f"securemailscope_report_{capture_id}.json"
    return JSONResponse(content=report_data, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/{capture_id}/report.html")
def get_report_html(capture_id: str, db: DBSession = Depends(get_db)) -> HTMLResponse:
    report_data = _load_report_data(capture_id, db)
    return HTMLResponse(content=render_html(report_data))


@router.get("/{capture_id}/report.pdf")
def get_report_pdf(capture_id: str, db: DBSession = Depends(get_db)) -> Response:
    report_data = _load_report_data(capture_id, db)
    try:
        pdf_bytes = render_pdf(report_data)
    except (ImportError, OSError) as exc:
        # WeasyPrint's native Pango/cairo/gdk-pixbuf libraries aren't installed in every
        # environment (notably a bare Windows dev machine, confirmed while building this
        # stage: `import weasyprint` itself raises OSError there, not ImportError, since
        # it dlopen()s libgobject at import time) - fail as a clear, recoverable 503
        # rather than a bare stack trace, since JSON/HTML export still work fine.
        raise HTTPException(
            status_code=503,
            detail=(
                "PDF rendering is unavailable: WeasyPrint's native dependencies are not "
                "installed in this environment. Use /report.json or /report.html instead."
            ),
        ) from exc

    filename = f"securemailscope_report_{capture_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
