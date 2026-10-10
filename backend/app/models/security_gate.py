"""SecurityGateResult ORM model."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Integer, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class SecurityGateResult(Base):
    __tablename__ = "security_gate_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=True
    )

    status: Mapped[str] = mapped_column(String(20), nullable=False)
    critical: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    info: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    reasons: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    scan: Mapped[Optional["Scan"]] = relationship(back_populates="gate_results")
