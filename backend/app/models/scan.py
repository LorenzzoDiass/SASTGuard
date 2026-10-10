"""Scan ORM model."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import String, Integer, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.enums import ScanStatus


def _uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.PENDING.value, nullable=False)

    source_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    total_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    findings: Mapped[List["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    gate_results: Mapped[List["SecurityGateResult"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
