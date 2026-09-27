"""Celery app + analysis task (Stage 7).

`task_always_eager` defaults to true so the task executes synchronously, in-process, the
moment `.delay()` is called - no Redis broker or separate worker process required. That
keeps `uvicorn app.main:app` and `pytest` zero-dependency, matching every prior stage's
"just run it" convention, on a machine (like this dev sandbox) that has no broker running.
`docker-compose.yml` sets `CELERY_TASK_ALWAYS_EAGER=false` for the real deployment, where a
`worker` service actually consumes from the `redis` service asynchronously as CLAUDE.md's
locked-in stack specifies.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from celery import Celery

from .db import SessionLocal, init_db
from .models.analysis import STATUS_COMPLETE, STATUS_FAILED, STATUS_RUNNING, Capture, SessionRecord

BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", BROKER_URL)
TASK_ALWAYS_EAGER = os.environ.get("CELERY_TASK_ALWAYS_EAGER", "true").lower() not in ("false", "0", "")

celery_app = Celery("securemailscope", broker=BROKER_URL, backend=RESULT_BACKEND)
celery_app.conf.task_always_eager = TASK_ALWAYS_EAGER
celery_app.conf.task_eager_propagates = True

UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", Path(__file__).resolve().parent.parent / "uploads"))


@celery_app.task(name="securemailscope.analyze_pcap")
def analyze_pcap_task(capture_id: str) -> None:
    from .api.pipeline import analyze_pcap_file  # local import: avoid a circular import with api/router.py

    init_db()
    db = SessionLocal()
    try:
        capture = db.get(Capture, capture_id)
        if capture is None:
            return

        capture.status = STATUS_RUNNING
        db.commit()

        pcap_path = UPLOAD_DIR / f"{capture_id}.pcap"
        try:
            result = analyze_pcap_file(pcap_path, capture.filename)
        except Exception as exc:  # a worker crash must not leave the row stuck PENDING/RUNNING forever
            capture.status = STATUS_FAILED
            capture.error = str(exc)
            db.commit()
            return

        for session_dict in result["sessions"]:
            db.add(SessionRecord(
                capture_id=capture_id,
                session_id=session_dict["session_id"],
                protocol=session_dict["protocol"],
                client_ip=session_dict["client"]["ip"],
                client_port=session_dict["client"]["port"],
                server_ip=session_dict["server"]["ip"],
                server_port=session_dict["server"]["port"],
                starttls=session_dict["starttls_negotiation"],
                tls_handshake=session_dict["tls_handshake"],
                certificate=session_dict["certificate"],
                findings=session_dict["findings"],
                posture_score=session_dict["posture_score"],
                risk_level=session_dict["risk_level"],
                ai_analysis=session_dict["ai_analysis"],
            ))

        capture.summary = result["summary"]
        capture.status = STATUS_COMPLETE
        capture.completed_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()
