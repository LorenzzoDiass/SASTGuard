"""Scan endpoints: create (JSON path or upload), list, detail, findings."""
from __future__ import annotations

import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.repositories import ScanRepository
from app.schemas import ScanCreate, ScanOut, ScanDetail, FindingOut
from app.services.upload import store_upload, UploadError
from app.workers.tasks import dispatch_scan

router = APIRouter(prefix="/api/scans", tags=["scans"],
                   dependencies=[Depends(get_current_user)])


def _semgrep_rules_path() -> Optional[str]:
    # repo-level semgrep_rules dir if present
    candidate = os.path.join(os.getcwd(), "semgrep_rules")
    return candidate if os.path.isdir(candidate) else None


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> ScanOut:
    """Create a scan for a server-side path (e.g. a mounted project or samples)."""
    if not payload.source_path or not os.path.exists(payload.source_path):
        raise HTTPException(status_code=400, detail="source_path does not exist on server")
    repo = ScanRepository(db)
    scan = repo.create_scan(payload.project_name, source_path=payload.source_path)
    dispatch_scan(scan.id, payload.source_path, run_ai=payload.run_ai,
                  semgrep_rules_path=_semgrep_rules_path())
    db.refresh(scan)
    return ScanOut.model_validate(scan)


@router.post("/upload", response_model=ScanOut, status_code=201)
async def create_scan_upload(
    project_name: str = Form(...),
    run_ai: bool = Form(False),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> ScanOut:
    """Create a scan from an uploaded .py file or .zip project (securely stored)."""
    content = await file.read()
    try:
        stored = store_upload(file.filename, content)
    except UploadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    repo = ScanRepository(db)
    scan = repo.create_scan(project_name, source_path=stored.scan_dir)
    dispatch_scan(scan.id, stored.scan_dir, run_ai=run_ai,
                  semgrep_rules_path=_semgrep_rules_path())
    db.refresh(scan)
    return ScanOut.model_validate(scan)


@router.get("", response_model=List[ScanOut])
def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> List[ScanOut]:
    repo = ScanRepository(db)
    return [ScanOut.model_validate(s) for s in repo.list_scans(limit=limit, offset=offset)]


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> ScanDetail:
    repo = ScanRepository(db)
    scan = repo.get_scan_with_findings(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanDetail.model_validate(scan)


@router.get("/{scan_id}/findings", response_model=List[FindingOut])
def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    file: Optional[str] = None,
    cwe: Optional[str] = None,
    engine: Optional[str] = None,
    db: Session = Depends(get_db),
) -> List[FindingOut]:
    repo = ScanRepository(db)
    if repo.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = repo.list_findings(scan_id, severity=severity, file_path=file,
                                  cwe=cwe, engine=engine)
    return [FindingOut.model_validate(f) for f in findings]
