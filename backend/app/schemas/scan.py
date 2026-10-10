"""Pydantic schemas for Scan resources."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from app.schemas.finding import FindingOut


class ScanCreate(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=255)
    # Optional server-side path to analyse (used by CLI / samples). Uploads use a file.
    source_path: Optional[str] = None
    run_ai: bool = False


class ScanOut(BaseModel):
    id: str
    project_name: str
    status: str
    source_path: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    finished_at: Optional[datetime] = None
    total_files: int
    total_findings: int

    model_config = {"from_attributes": True}


class ScanDetail(ScanOut):
    findings: List[FindingOut] = []
