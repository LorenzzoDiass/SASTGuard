"""Dashboard aggregation service built on top of the repository."""
from __future__ import annotations

from typing import List

from sqlalchemy.orm import Session

from app.core.enums import Severity
from app.repositories import ScanRepository


class DashboardService:
    def __init__(self, db: Session):
        self.repo = ScanRepository(db)

    def summary(self) -> dict:
        totals = self.repo.severity_totals()
        latest = self.repo.latest_scan()
        return {
            "total_vulnerabilities": sum(totals.values()),
            "critical": totals.get(Severity.CRITICAL.value, 0),
            "high": totals.get(Severity.HIGH.value, 0),
            "medium": totals.get(Severity.MEDIUM.value, 0),
            "low": totals.get(Severity.LOW.value, 0),
            "info": totals.get(Severity.INFO.value, 0),
            "total_scans": self.repo.total_scans(),
            "last_scan_findings": latest.total_findings if latest else 0,
        }

    def severity_distribution(self) -> List[dict]:
        totals = self.repo.severity_totals()
        return [
            {"severity": s.value, "count": totals.get(s.value, 0)}
            for s in Severity
        ]

    def trends(self, limit: int = 10) -> List[dict]:
        """Per-scan severity breakdown for the trend chart (most recent first)."""
        scans = self.repo.list_scans(limit=limit)
        points: List[dict] = []
        for scan in scans:
            counts = {s.value: 0 for s in Severity}
            for f in scan.findings:
                counts[f.severity] = counts.get(f.severity, 0) + 1
            points.append({
                "scan_id": scan.id,
                "project_name": scan.project_name,
                "created_at": scan.created_at.isoformat(),
                "critical": counts[Severity.CRITICAL.value],
                "high": counts[Severity.HIGH.value],
                "medium": counts[Severity.MEDIUM.value],
                "low": counts[Severity.LOW.value],
                "total": scan.total_findings,
            })
        points.reverse()  # chronological for charts
        return points

    def critical_files(self, limit: int = 5) -> List[dict]:
        return self.repo.critical_files(limit=limit)
