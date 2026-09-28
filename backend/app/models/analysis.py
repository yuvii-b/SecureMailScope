"""Persistence models for analysis results (Stage 7).

A `Capture` is one uploaded pcap and its job lifecycle; each `SessionRecord` is one
reconstructed session within it. The nested evidence (`starttls`, `tls_handshake`,
`certificate`, `findings`) is stored as JSON columns rather than further normalized
tables - there's no cross-session query requirement yet (e.g. "all findings of severity
X across every capture") to justify that extra schema complexity, and the JSON already
matches what the rule engine (Stage 6) and the §7 API contract produce. Revisit if a
later stage (e.g. ML training data export) needs to query into finding fields directly.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base

STATUS_PENDING = "PENDING"
STATUS_RUNNING = "RUNNING"
STATUS_COMPLETE = "COMPLETE"
STATUS_FAILED = "FAILED"


def _new_id() -> str:
    return uuid.uuid4().hex


class Capture(Base):
    __tablename__ = "captures"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    filename: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default=STATUS_PENDING)
    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    sessions: Mapped[list["SessionRecord"]] = relationship(
        back_populates="capture", cascade="all, delete-orphan"
    )

    def to_dict(self, include_sessions: bool = False) -> dict:
        body = {
            "capture_id": self.id,
            "filename": self.filename,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "summary": self.summary,
        }
        if include_sessions:
            body["sessions"] = [s.to_dict() for s in self.sessions]
        return body


class SessionRecord(Base):
    __tablename__ = "session_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id"))
    session_id: Mapped[str] = mapped_column(String(64))
    protocol: Mapped[str] = mapped_column(String(16))
    client_ip: Mapped[str] = mapped_column(String(64))
    client_port: Mapped[int] = mapped_column(Integer)
    server_ip: Mapped[str] = mapped_column(String(64))
    server_port: Mapped[int] = mapped_column(Integer)
    starttls: Mapped[dict] = mapped_column(JSON)
    tls_handshake: Mapped[dict] = mapped_column(JSON)
    certificate: Mapped[dict] = mapped_column(JSON)
    findings: Mapped[list] = mapped_column(JSON)
    posture_score: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[str] = mapped_column(String(16))
    ai_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Stage 10: both purely additive/nullable, so existing rows and code paths that don't
    # set them (e.g. the synchronous debug endpoint) are unaffected.
    crypto_fingerprint: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    drift: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    capture: Mapped["Capture"] = relationship(back_populates="sessions")

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "client": {"ip": self.client_ip, "port": self.client_port},
            "server": {"ip": self.server_ip, "port": self.server_port},
            "starttls_negotiation": self.starttls,
            "tls_handshake": self.tls_handshake,
            "certificate": self.certificate,
            "ai_analysis": self.ai_analysis,
            "crypto_fingerprint": self.crypto_fingerprint,
            "drift": self.drift,
            "findings": self.findings,
            "posture_score": self.posture_score,
            "risk_level": self.risk_level,
        }
