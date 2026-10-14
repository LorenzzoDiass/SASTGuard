"""Security primitives: password hashing and JWT creation/verification.

Password hashing uses bcrypt via passlib. Tokens are signed JWTs (HS256 by
default) carrying the user id (``sub``), username and admin flag. All of this
depends on optional packages (``passlib[bcrypt]`` and ``python-jose``) that are
declared in requirements and installed in CI / Docker / deploy. The imports are
tolerant so the rest of the app still imports on a machine without them; auth
endpoints then surface a clear error instead of crashing at import time.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from app.core.config import settings

logger = logging.getLogger("sastguard.security")

# --- optional crypto deps -------------------------------------------------
try:
    from passlib.context import CryptContext

    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    _PASSLIB_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001
    _pwd_context = None
    _PASSLIB_ERROR = str(exc)

try:
    from jose import jwt, JWTError

    _JOSE_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001
    jwt = None  # type: ignore[assignment]
    JWTError = Exception  # type: ignore[assignment,misc]
    _JOSE_ERROR = str(exc)


class AuthDependencyError(RuntimeError):
    """Raised when an auth operation needs a package that is not installed."""


def crypto_available() -> bool:
    return _pwd_context is not None and jwt is not None


def missing_dependency_message() -> Optional[str]:
    parts = []
    if _pwd_context is None:
        parts.append(f"passlib/bcrypt unavailable ({_PASSLIB_ERROR})")
    if jwt is None:
        parts.append(f"python-jose unavailable ({_JOSE_ERROR})")
    return "; ".join(parts) or None


# --- passwords ------------------------------------------------------------
def hash_password(password: str) -> str:
    if _pwd_context is None:
        raise AuthDependencyError(missing_dependency_message())
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    if _pwd_context is None:
        raise AuthDependencyError(missing_dependency_message())
    try:
        return _pwd_context.verify(plain, hashed)
    except Exception:  # noqa: BLE001 - malformed hash -> treat as mismatch
        return False


# --- tokens ---------------------------------------------------------------
def create_access_token(subject: str, username: str, is_admin: bool,
                        expires_minutes: Optional[int] = None) -> str:
    if jwt is None:
        raise AuthDependencyError(missing_dependency_message())
    expire_minutes = expires_minutes or settings.access_token_expire_minutes
    now = datetime.utcnow()
    payload = {
        "sub": subject,
        "username": username,
        "is_admin": is_admin,
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> Optional[dict]:
    """Return the token payload, or None when invalid/expired."""
    if jwt is None:
        raise AuthDependencyError(missing_dependency_message())
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None


_INSECURE_SECRET_DEFAULT = "dev-insecure-change-me"


def _is_production() -> bool:
    return settings.app_env.strip().lower() in ("production", "prod")


def enforce_security_posture() -> None:
    """Fail closed on insecure production configuration; warn in dev.

    Production (APP_ENV=production) requirements, enforced at startup:
      * Authentication must be enabled (no accidental AUTH_ENABLED=false bypass).
      * SECRET_KEY must not be the insecure development default.
    Violations raise RuntimeError so the service refuses to start misconfigured.
    In non-production environments these are warnings only, so local dev and the
    CLI/tests keep working.
    """
    if _is_production():
        if not settings.auth_enabled:
            raise RuntimeError(
                "Refusing to start: APP_ENV=production requires AUTH_ENABLED=true "
                "(authentication must not be disabled in production)."
            )
        if settings.secret_key == _INSECURE_SECRET_DEFAULT or len(settings.secret_key) < 16:
            raise RuntimeError(
                "Refusing to start: a strong SECRET_KEY is required in production "
                "(set a long random value, e.g. `openssl rand -hex 32`)."
            )
        return

    # Non-production: warn but allow.
    if settings.auth_enabled and settings.secret_key == _INSECURE_SECRET_DEFAULT:
        logger.warning(
            "SECURITY: SECRET_KEY is the insecure default. Set a strong SECRET_KEY "
            "before deploying. (Allowed now because APP_ENV=%s.)", settings.app_env,
        )
    if not settings.auth_enabled:
        logger.warning(
            "AUTH_ENABLED=false: the API is OPEN. This is only acceptable for the "
            "CLI/CI context or a local demo, never in production."
        )


# Backwards-compatible alias (previously named warn_if_insecure_secret).
def warn_if_insecure_secret() -> None:
    enforce_security_posture()
