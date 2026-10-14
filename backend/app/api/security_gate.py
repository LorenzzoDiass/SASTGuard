"""Security Gate evaluation endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.repositories import ScanRepository
from app.models import SecurityGateResult
from app.schemas import GateEvaluateRequest, GateResultOut
from app.services.security_gate import evaluate_gate, GatePolicy

router = APIRouter(prefix="/api/security-gate", tags=["security-gate"],
                   dependencies=[Depends(get_current_user)])


@router.post("/evaluate", response_model=GateResultOut)
def evaluate(payload: GateEvaluateRequest, db: Session = Depends(get_db)) -> GateResultOut:
    """Evaluate the security gate for a scan's findings against a policy."""
    repo = ScanRepository(db)
    if not payload.scan_id:
        raise HTTPException(status_code=400, detail="scan_id is required")
    scan = repo.get_scan_with_findings(payload.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    counts = {}
    for f in scan.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    policy = GatePolicy()
    if payload.policy:
        policy = GatePolicy(
            fail_critical=payload.policy.fail_critical,
            fail_high=payload.policy.fail_high,
            warn_medium=payload.policy.warn_medium,
        )

    evaluation = evaluate_gate(counts, policy)

    # Persist the result for history.
    repo.save_gate_result(SecurityGateResult(
        scan_id=scan.id,
        status=evaluation.status.value,
        critical=evaluation.critical,
        high=evaluation.high,
        medium=evaluation.medium,
        low=evaluation.low,
        info=evaluation.info,
        reasons=evaluation.reasons,
        policy=policy.to_dict(),
    ))

    return GateResultOut(**evaluation.to_dict())
