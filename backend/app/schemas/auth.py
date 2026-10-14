"""Pydantic schemas for authentication."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: "UserOut"


class UserOut(BaseModel):
    id: str
    username: str
    is_admin: bool
    is_active: bool

    model_config = {"from_attributes": True}


TokenResponse.model_rebuild()
