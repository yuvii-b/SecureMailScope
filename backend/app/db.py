"""SQLAlchemy engine/session setup (Stage 7).

`DATABASE_URL` defaults to a local SQLite file so the API and test suite run with zero
external services - matching every prior stage's "just run pytest" convention. The locked
stack (CLAUDE.md §3) is PostgreSQL for real deployment: `docker-compose.yml` points
`DATABASE_URL` at the `postgres` service container, this default is only the dependency-free
fallback for a laptop without that container running.
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./securemailscope.db")

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from . import models  # noqa: F401  (registers models on Base.metadata)

    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
