"""AIAnalysis ORM model - stores LLM-produced analysis for a finding."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Text, Float, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, unique=True
    )

    available: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    model: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    ai_severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    possible_false_positive: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    explanation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    impact: Mapped[str] = mapped_column(Text, default="", nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    fixed_code: Mapped[str] = mapped_column(Text, default="", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="ai_analysis")
