"""Finding endpoints: detail and on-demand AI analysis."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ai.analyzer import AIAnalyzer
from app.core.database import get_db
from app.core.deps import get_current_user
from app.repositories import ScanRepository
from app.schemas import FindingOut

router = APIRouter(prefix="/api/findings", tags=["findings"],
                   dependencies=[Depends(get_current_user)])


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: Session = Depends(get_db)) -> FindingOut:
    repo = ScanRepository(db)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingOut.model_validate(finding)


@router.post("/{finding_id}/ai-analysis", response_model=FindingOut)
def run_ai_analysis(finding_id: str, db: Session = Depends(get_db)) -> FindingOut:
    """Run (or re-run) AI analysis for a single finding.

    If Ollama is unavailable the stored analysis is marked unavailable with the
    'AI analysis unavailable' message; the finding is never lost.
    """
    repo = ScanRepository(db)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    analyzer = AIAnalyzer()
    result = analyzer.analyze({
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
    })
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
    db.refresh(finding)
    return FindingOut.model_validate(finding)
