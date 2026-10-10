"""Pydantic schemas for the Security Gate."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel

from app.core.config import settings


class GatePolicy(BaseModel):
    fail_critical: int = settings.gate_fail_critical
    fail_high: int = settings.gate_fail_high
    warn_medium: int = settings.gate_warn_medium


class GateEvaluateRequest(BaseModel):
    scan_id: Optional[str] = None
    policy: Optional[GatePolicy] = None


class GateResultOut(BaseModel):
    status: str
    critical: int
    high: int
    medium: int
    low: int
    info: int = 0
    reasons: List[str] = []
