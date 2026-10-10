"""Pydantic schemas for Finding resources."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

from app.schemas.ai_analysis import AIAnalysisOut


class TaintStepOut(BaseModel):
    kind: str
    description: str
    line: int
    code: str = ""


class FindingOut(BaseModel):
    id: str
    scan_id: str
    rule_id: str
    title: str
    description: str
    file_path: str
    line: int
    column: int
    code_snippet: str
    severity: str
    original_severity: str
    confidence: float
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    recommendation: str
    engines: List[str] = []
    taint_path: Optional[List[TaintStepOut]] = None
    status: str
    created_at: datetime
    ai_analysis: Optional[AIAnalysisOut] = None

    model_config = {"from_attributes": True}
