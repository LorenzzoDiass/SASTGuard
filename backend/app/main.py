"""SASTGuard FastAPI application entrypoint."""
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.core.config import settings
from app.core.database import init_db
from app.core.security import enforce_security_posture
from app.core.bootstrap import ensure_admin_user
from app.api import health, scans, findings, dashboard, security_gate, auth

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Static Application Security Testing & DevSecOps platform.",
    )

    # Credentials are not used (stateless Bearer tokens), so we can scope origins
    # explicitly instead of the invalid "*" + allow_credentials combination.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(dashboard.router)
    app.include_router(security_gate.router)

    # Fail closed on insecure production configuration BEFORE building the app.
    enforce_security_posture()

    @app.on_event("startup")
    def _startup() -> None:
        init_db()
        ensure_admin_user()
        logging.getLogger("sastguard").info("%s %s started", settings.app_name, __version__)

    @app.get("/")
    def root() -> dict:
        return {"app": settings.app_name, "docs": "/docs", "health": "/health"}

    return app


app = create_app()
