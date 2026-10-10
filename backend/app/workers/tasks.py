"""Celery tasks that execute scans in the background."""
from __future__ import annotations

import logging
from typing import Optional

from app.core.database import SessionLocal
from app.services.scan_service import run_scan

logger = logging.getLogger("sastguard.worker")


def _run(scan_id: str, target_path: str, run_ai: bool,
         semgrep_rules_path: Optional[str]) -> dict:
    """Shared execution body with its own DB session."""
    db = SessionLocal()
    try:
        return run_scan(
            db,
            scan_id=scan_id,
            target_path=target_path,
            run_ai=run_ai,
            semgrep_rules_path=semgrep_rules_path,
        )
    finally:
        db.close()


# Register the Celery task lazily to avoid a hard import cycle at module load.
def _register():
    from app.workers.celery_app import celery_app

    @celery_app.task(name="sastguard.run_scan", bind=True)
    def run_scan_task(self, scan_id: str, target_path: str,
                      run_ai: bool = False, semgrep_rules_path: str = None):
        logger.info("Worker picked up scan %s", scan_id)
        return _run(scan_id, target_path, run_ai, semgrep_rules_path)

    return run_scan_task


try:
    run_scan_task = _register()
except Exception as exc:  # noqa: BLE001 - allow import without broker in tests
    logging.getLogger("sastguard.worker").debug("Celery task registration deferred: %s", exc)
    run_scan_task = None


def dispatch_scan(scan_id: str, target_path: str, run_ai: bool = False,
                  semgrep_rules_path: Optional[str] = None) -> str:
    """Dispatch a scan.

    If a Celery broker is reachable, enqueue the task and return "queued".
    Otherwise fall back to running synchronously (so local dev without Redis
    still works) and return "completed-sync".
    """
    from app.workers.celery_app import celery_app

    try:
        # Probe the broker; if unreachable this raises quickly.
        conn = celery_app.connection()
        conn.ensure_connection(max_retries=1, timeout=2)
        conn.release()
        run_scan_task.delay(scan_id, target_path, run_ai, semgrep_rules_path)
        logger.info("Scan %s queued to Celery", scan_id)
        return "queued"
    except Exception as exc:  # noqa: BLE001 - broker down -> run inline
        logger.warning("Broker unavailable (%s); running scan %s synchronously",
                       exc, scan_id)
        _run(scan_id, target_path, run_ai, semgrep_rules_path)
        return "completed-sync"
