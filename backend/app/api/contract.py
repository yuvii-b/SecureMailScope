"""Shared helper for building the §7 contract response for a persisted capture (Stage 7/11).

Used by both the analyses API (`api/router.py`) and the report renderers
(`reports/renderer.py`) so the two never drift apart on what "the completed analysis"
looks like - the report is a rendered *view* of this dict, never a second computation
of it.
"""
from __future__ import annotations

from ..models.analysis import Capture, SessionRecord
from .pipeline import SCHEMA_VERSION


def build_contract(capture: Capture, sessions: list[SessionRecord]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "capture_id": capture.id,
        "status": capture.status,
        "summary": capture.summary,
        "sessions": [s.to_dict() for s in sessions],
    }
