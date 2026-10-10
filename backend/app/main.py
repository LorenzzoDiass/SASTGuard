"""SASTGuard FastAPI application entrypoint."""
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.core.config import settings
from app.core.database import init_db
from app.api import health, scans, findings, dashboard, security_gate

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Static Application Security Testing & DevSecOps platform.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # dashboard dev server; tighten in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(dashboard.router)
    app.include_router(security_gate.router)

    @app.on_event("startup")
    def _startup() -> None:
        init_db()
        logging.getLogger("sastguard").info("%s %s started", settings.app_name, __version__)

    @app.get("/")
    def root() -> dict:
        return {"app": settings.app_name, "docs": "/docs", "health": "/health"}

    return app


app = create_app()
