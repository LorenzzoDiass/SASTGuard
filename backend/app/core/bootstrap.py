"""Startup bootstrap: optionally create the first admin user.

Security posture:
* No default credentials. An admin is created ONLY when ``ADMIN_PASSWORD`` is
  provided via the environment. If it is not set, no user is created and a
  warning is logged (the password itself is NEVER logged or generated).
* Runs only when auth is enabled and the crypto deps are available.
* Idempotent: if any user already exists, nothing happens.
"""
from __future__ import annotations

import logging

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import hash_password, crypto_available, missing_dependency_message
from app.repositories import UserRepository

logger = logging.getLogger("sastguard.bootstrap")


def ensure_admin_user() -> None:
    if not settings.auth_enabled:
        logger.info("Auth disabled (AUTH_ENABLED=false); skipping admin bootstrap.")
        return
    if not crypto_available():
        logger.warning(
            "Auth enabled but crypto deps missing (%s); cannot bootstrap admin.",
            missing_dependency_message(),
        )
        return

    db = SessionLocal()
    try:
        repo = UserRepository(db)
        if repo.count() > 0:
            return

        username = settings.admin_username
        password = settings.admin_password
        if not password:
            # No default credentials and no generated/logged password.
            logger.warning(
                "No admin user exists and ADMIN_PASSWORD is not set. No admin was "
                "created. Set ADMIN_USERNAME and ADMIN_PASSWORD in the environment "
                "and restart to create the first administrator."
            )
            return

        repo.create(
            username=username,
            password_hash=hash_password(password),
            is_admin=True,
        )
        # Log the fact, never the credential.
        logger.info("Bootstrapped initial admin user '%s'.", username)
    finally:
        db.close()
