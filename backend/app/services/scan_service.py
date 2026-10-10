"""Scan orchestration service.

Runs the SAST engine over a target, persists findings, and optionally triggers
AI enrichment. Used both by the Celery worker (async) and directly (sync CLI).
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

from ai.analyzer import AIAnalyzer
from app.core.enums import ScanStatus
from app.models import Finding as FindingModel
from app.repositories import ScanRepository
from sast.engine import SastEngine, severity_counts

logger = logging.getLogger("sastguard.scan")


def _to_model(scan_id: str, f) -> FindingModel:
    """Convert an engine Finding dataclass into an ORM Finding."""
    taint = [s.to_dict() for s in f.taint_path] if f.taint_path else None
    return FindingModel(
        scan_id=scan_id,
        rule_id=f.rule_id,
        title=f.title,
        description=f.description,
        file_path=f.file_path,
        line=f.line,
        column=f.column,
        code_snippet=f.code_snippet,
        severity=f.severity.value,
        original_severity=f.severity.value,
        confidence=f.confidence,
        cwe=f.cwe,
        owasp=f.owasp,
        recommendation=f.recommendation,
        engines=list(f.engines),
        taint_path=taint,
    )


def run_scan(db: Session, scan_id: str, target_path: str,
             run_ai: bool = False, semgrep_rules_path: Optional[str] = None) -> dict:
    """Execute a scan end-to-end and persist results.

    Returns a summary dict. Never raises past updating the scan to FAILED.
    """
    repo = ScanRepository(db)
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"Scan {scan_id} not found")

    repo.update_status(scan, ScanStatus.RUNNING)
    try:
        engine = SastEngine(semgrep_rules_path=semgrep_rules_path)
        result = engine.scan_path(target_path)

        models = [_to_model(scan_id, f) for f in result.findings]
        repo.add_findings(scan, models)
        repo.set_scan_totals(scan, result.total_files, len(models))
        repo.update_status(scan, ScanStatus.COMPLETED)

        if run_ai:
            _enrich_with_ai(repo, models)

        counts = severity_counts(result.findings)
        logger.info("Scan %s completed: %d findings", scan_id, len(models))
        return {
            "scan_id": scan_id,
            "status": ScanStatus.COMPLETED.value,
            "total_files": result.total_files,
            "total_findings": len(models),
            "severity_counts": counts,
            "engines_run": result.engines_run,
            "engines_available": result.engines_available,
        }
    except Exception as exc:  # noqa: BLE001 - record failure, do not crash worker
        logger.exception("Scan %s failed", scan_id)
        repo.update_status(scan, ScanStatus.FAILED, error_message=str(exc))
        return {"scan_id": scan_id, "status": ScanStatus.FAILED.value, "error": str(exc)}


def _enrich_with_ai(repo: ScanRepository, findings) -> None:
    """Run AI analysis for the most severe findings (keeps it bounded)."""
    analyzer = AIAnalyzer()
    # Only enrich CRITICAL/HIGH to keep runtime reasonable.
    targets = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    for finding in targets:
        finding_dict = {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            "file_path": finding.file_path,
            "line": finding.line,
            "description": finding.description,
            "code_snippet": finding.code_snippet,
            "taint_path": finding.taint_path,
        }
        result = analyzer.analyze(finding_dict)
        repo.upsert_ai_analysis(finding, {
            "available": result.available,
            "model": result.model,
            "ai_severity": result.ai_severity,
            "confidence": result.confidence,
            "possible_false_positive": result.possible_false_positive,
            "explanation": result.explanation,
            "impact": result.impact,
            "remediation": result.remediation,
            "fixed_code": result.fixed_code,
        })
