"""Database engine, session factory and declarative base."""
from __future__ import annotations

from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session

from app.core.config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _make_engine():
    url = settings.database_url
    connect_args = {}
    if url.startswith("sqlite"):
        # Needed so SQLite can be shared across threads (FastAPI/Celery).
        connect_args = {"check_same_thread": False}
    return create_engine(url, pool_pre_ping=True, connect_args=connect_args, future=True)


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    """Create any MISSING tables for fresh databases (dev/SQLite/tests).

    IMPORTANT: ``create_all`` only creates tables that do not yet exist. It does
    NOT alter existing tables, so it will not add new columns (e.g.
    ``findings.language``) to a database that was created by an earlier version.

    For an existing/production database (PostgreSQL), schema changes MUST be
    applied with the Alembic migrations in ``backend/migrations`` (``alembic
    upgrade head``), which are non-destructive. This function remains for a
    convenient first-run on a brand-new database and for the test suite.
    """
    from app import models  # noqa: F401  (ensures models are imported)

    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a scoped DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
