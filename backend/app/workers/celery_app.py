"""Celery application for asynchronous SAST scans."""
from __future__ import annotations

from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "sastguard",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=1800,          # 30 min hard limit per scan
    task_soft_time_limit=1500,
    worker_max_tasks_per_child=50,
)

# Ensure tasks are registered when the worker starts.
celery_app.autodiscover_tasks(["app.workers"])

# Import the task module so it registers even without autodiscover.
from app.workers import tasks  # noqa: E402,F401
