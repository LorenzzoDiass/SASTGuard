"""Data-access layer for users."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_username(self, username: str) -> Optional[User]:
        stmt = select(User).where(User.username == username)
        return self.db.execute(stmt).scalar_one_or_none()

    def get_by_id(self, user_id: str) -> Optional[User]:
        return self.db.get(User, user_id)

    def create(self, username: str, password_hash: str, is_admin: bool = False) -> User:
        user = User(username=username, password_hash=password_hash, is_admin=is_admin)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def count(self) -> int:
        from sqlalchemy import func
        return self.db.execute(select(func.count(User.id))).scalar_one()

    def touch_login(self, user: User) -> None:
        user.last_login_at = datetime.utcnow()
        self.db.commit()
