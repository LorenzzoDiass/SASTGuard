"""Pydantic schemas for dashboard aggregations."""
from __future__ import annotations

from typing import List

from pydantic import BaseModel


class DashboardSummary(BaseModel):
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    total_scans: int
    last_scan_findings: int


class SeverityDistribution(BaseModel):
    severity: str
    count: int


class TrendPoint(BaseModel):
    scan_id: str
    project_name: str
    created_at: str
    critical: int
    high: int
    medium: int
    low: int
    total: int


class CriticalFile(BaseModel):
    file_path: str
    critical: int
    high: int
    total: int
