"""Data-access layer for scans, findings, AI analyses and gate results."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy import select, func
from sqlalchemy.orm import Session, selectinload

from app.core.enums import ScanStatus
from app.models import Scan, Finding, AIAnalysis, SecurityGateResult


class ScanRepository:
    def __init__(self, db: Session):
        self.db = db

    # --- scans ----------------------------------------------------------
    def create_scan(self, project_name: str, source_path: Optional[str] = None) -> Scan:
        scan = Scan(project_name=project_name, source_path=source_path,
                    status=ScanStatus.PENDING.value)
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def get_scan(self, scan_id: str) -> Optional[Scan]:
        return self.db.get(Scan, scan_id)

    def get_scan_with_findings(self, scan_id: str) -> Optional[Scan]:
        stmt = (
            select(Scan)
            .where(Scan.id == scan_id)
            .options(selectinload(Scan.findings).selectinload(Finding.ai_analysis))
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def list_scans(self, limit: int = 50, offset: int = 0) -> List[Scan]:
        stmt = (
            select(Scan)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.execute(stmt).scalars().all())

    def list_scans_with_findings(self, limit: int = 50, offset: int = 0) -> List[Scan]:
        """Like :meth:`list_scans` but eager-loads findings in one query.

        Used by dashboard trends to avoid an N+1 (one extra query per scan when
        counting severities).
        """
        stmt = (
            select(Scan)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(offset)
            .options(selectinload(Scan.findings))
        )
        return list(self.db.execute(stmt).scalars().all())

    def update_status(self, scan: Scan, status: ScanStatus,
                      error_message: Optional[str] = None) -> Scan:
        scan.status = status.value
        if error_message is not None:
            scan.error_message = error_message
        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            scan.finished_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def set_scan_totals(self, scan: Scan, total_files: int, total_findings: int) -> None:
        scan.total_files = total_files
        scan.total_findings = total_findings
        self.db.commit()

    # --- findings -------------------------------------------------------
    def add_findings(self, scan: Scan, findings: List[Finding]) -> None:
        self.db.add_all(findings)
        self.db.commit()

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        stmt = (
            select(Finding)
            .where(Finding.id == finding_id)
            .options(selectinload(Finding.ai_analysis))
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def list_findings(self, scan_id: str, severity: Optional[str] = None,
                      file_path: Optional[str] = None, cwe: Optional[str] = None,
                      engine: Optional[str] = None) -> List[Finding]:
        stmt = (
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .options(selectinload(Finding.ai_analysis))
        )
        if severity:
            stmt = stmt.where(Finding.severity == severity.upper())
        if file_path:
            stmt = stmt.where(Finding.file_path.like(f"%{file_path}%"))
        if cwe:
            stmt = stmt.where(Finding.cwe == cwe)
        findings = list(self.db.execute(stmt).scalars().all())
        if engine:
            findings = [f for f in findings if engine in (f.engines or [])]
        return findings

    # --- ai analysis ----------------------------------------------------
    def upsert_ai_analysis(self, finding: Finding, data: dict) -> AIAnalysis:
        existing = finding.ai_analysis
        if existing:
            for key, value in data.items():
                setattr(existing, key, value)
            self.db.commit()
            self.db.refresh(existing)
            return existing
        analysis = AIAnalysis(finding_id=finding.id, **data)
        self.db.add(analysis)
        # mirror AI severity onto the finding (keeping original_severity intact)
        if data.get("ai_severity"):
            finding.severity = data["ai_severity"]
        self.db.commit()
        self.db.refresh(analysis)
        return analysis

    # --- gate -----------------------------------------------------------
    def save_gate_result(self, result: SecurityGateResult) -> SecurityGateResult:
        self.db.add(result)
        self.db.commit()
        self.db.refresh(result)
        return result

    # --- dashboard aggregations ----------------------------------------
    def total_scans(self) -> int:
        return self.db.execute(select(func.count(Scan.id))).scalar_one()

    def severity_totals(self) -> dict:
        stmt = select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
        rows = self.db.execute(stmt).all()
        return {sev: count for sev, count in rows}

    def language_totals(self) -> dict:
        """Count findings grouped by source language (single grouped query)."""
        stmt = select(Finding.language, func.count(Finding.id)).group_by(Finding.language)
        rows = self.db.execute(stmt).all()
        return {(lang or "python"): count for lang, count in rows}

    def latest_scan(self) -> Optional[Scan]:
        stmt = select(Scan).order_by(Scan.created_at.desc()).limit(1)
        return self.db.execute(stmt).scalar_one_or_none()

    def recent_scans(self, limit: int = 5) -> List[Scan]:
        return self.list_scans(limit=limit)

    def critical_files(self, limit: int = 5) -> List[dict]:
        """Return files ranked by critical+high finding counts.

        Aggregation is done in Python to stay portable across SQLite/Postgres.
        """
        findings = list(self.db.execute(select(Finding.file_path, Finding.severity)).all())
        agg: dict = {}
        for file_path, severity in findings:
            entry = agg.setdefault(file_path, {"critical": 0, "high": 0, "total": 0})
            entry["total"] += 1
            if severity == "CRITICAL":
                entry["critical"] += 1
            elif severity == "HIGH":
                entry["high"] += 1
        ranked = sorted(
            ({"file_path": k, **v} for k, v in agg.items()),
            key=lambda x: (-x["critical"], -x["high"], -x["total"]),
        )
        return ranked[:limit]
