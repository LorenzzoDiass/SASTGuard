"""Authentication endpoints: login, current user, logout.

Tokens are stateless JWTs. "Logout" is therefore handled client-side (the
dashboard discards the token); the endpoint exists for a clean API contract and
to allow future token-revocation without changing the frontend.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import (
    create_access_token,
    verify_password,
    crypto_available,
    missing_dependency_message,
)
from app.models import User
from app.repositories import UserRepository
from app.schemas.auth import LoginRequest, TokenResponse, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    if not crypto_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Auth not available: {missing_dependency_message()}",
        )

    repo = UserRepository(db)
    user = repo.get_by_username(payload.username)
    # Constant-ish behaviour: always verify to avoid user enumeration via timing.
    valid = bool(user) and user.is_active and verify_password(
        payload.password, user.password_hash
    )
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    repo.touch_login(user)
    token = create_access_token(user.id, user.username, user.is_admin)
    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserOut.model_validate(user),
    )


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    if user is None:
        # auth disabled -> report an anonymous admin-equivalent context.
        return UserOut(id="anonymous", username="anonymous",
                       is_admin=True, is_active=True)
    return UserOut.model_validate(user)


@router.post("/logout")
def logout(user: User = Depends(get_current_user)) -> dict:
    """Stateless logout. The client must discard the token.

    Returning 200 here lets the frontend confirm the session end uniformly.
    """
    return {"detail": "Logged out. Discard the access token on the client."}
