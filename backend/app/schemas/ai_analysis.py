"""Pydantic schemas for AIAnalysis."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AIAnalysisOut(BaseModel):
    id: str
    finding_id: str
    available: bool
    model: Optional[str] = None
    ai_severity: Optional[str] = None
    confidence: Optional[float] = None
    possible_false_positive: Optional[bool] = None
    explanation: str
    impact: str
    remediation: str
    fixed_code: str
    created_at: datetime

    model_config = {"from_attributes": True}
