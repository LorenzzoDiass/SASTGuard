"""Dashboard aggregation endpoints."""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas import DashboardSummary, SeverityDistribution, TrendPoint, CriticalFile
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(db: Session = Depends(get_db)) -> DashboardSummary:
    return DashboardSummary(**DashboardService(db).summary())


@router.get("/severity", response_model=List[SeverityDistribution])
def severity(db: Session = Depends(get_db)) -> List[SeverityDistribution]:
    return [SeverityDistribution(**d) for d in DashboardService(db).severity_distribution()]


@router.get("/trends", response_model=List[TrendPoint])
def trends(limit: int = Query(10, ge=1, le=50), db: Session = Depends(get_db)) -> List[TrendPoint]:
    return [TrendPoint(**p) for p in DashboardService(db).trends(limit=limit)]


@router.get("/critical-files", response_model=List[CriticalFile])
def critical_files(limit: int = Query(5, ge=1, le=20),
                   db: Session = Depends(get_db)) -> List[CriticalFile]:
    return [CriticalFile(**c) for c in DashboardService(db).critical_files(limit=limit)]
