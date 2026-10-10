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
    """Create all tables. Import models so they register on the metadata."""
    from app import models  # noqa: F401  (ensures models are imported)

    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a scoped DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
