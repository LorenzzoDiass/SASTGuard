"""Finding ORM model - represents a single detected vulnerability."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import String, Integer, DateTime, Text, Float, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    rule_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    file_path: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    line: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    column: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    code_snippet: Mapped[str] = mapped_column(Text, default="", nullable=False)

    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    original_severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)

    cwe: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    owasp: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # List of engines that reported this finding, e.g. ["ast", "bandit"]
    engines: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    # Ordered taint path steps when applicable
    taint_path: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    status: Mapped[str] = mapped_column(String(30), default="OPEN", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    ai_analysis: Mapped[Optional["AIAnalysis"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )
