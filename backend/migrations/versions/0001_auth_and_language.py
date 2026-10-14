"""Add users table and findings.language (non-destructive, idempotent).

Revision ID: 0001_auth_and_language
Revises:
Create Date: 2026-10-14

This migration is deliberately hand-written and safe for an EXISTING database
with data:

* It never drops or recreates existing tables and never deletes rows.
* It inspects the live schema first and only creates ``users`` if absent and
  only adds ``findings.language`` if that column is absent, so re-running it (or
  running it on a DB where ``create_all`` already created the objects) is a
  no-op rather than an error.
* ``findings.language`` is added with server_default='python' so every existing
  row is backfilled to the correct historical value (all prior findings were
  Python). The default is then dropped so the application layer owns the value
  going forward.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001_auth_and_language"
down_revision = None
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(name: str) -> bool:
    return name in _inspector().get_table_names()


def _has_column(table: str, column: str) -> bool:
    if not _has_table(table):
        return False
    return any(c["name"] == column for c in _inspector().get_columns(table))


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    # 1) users table ------------------------------------------------------
    if not _has_table("users"):
        op.create_table(
            "users",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("username", sa.String(length=150), nullable=False),
            sa.Column("password_hash", sa.String(length=255), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False,
                      server_default=sa.true()),
            sa.Column("is_admin", sa.Boolean(), nullable=False,
                      server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("last_login_at", sa.DateTime(), nullable=True),
        )
        op.create_index("ix_users_username", "users", ["username"], unique=True)

    # 2) findings.language -----------------------------------------------
    if _has_table("findings") and not _has_column("findings", "language"):
        # Add with a server default so existing rows are backfilled safely.
        op.add_column(
            "findings",
            sa.Column("language", sa.String(length=20), nullable=False,
                      server_default="python"),
        )
        # Drop the server default so the app controls the value going forward.
        # SQLite cannot ALTER a column default; it is harmless to leave there.
        if not is_sqlite:
            op.alter_column("findings", "language", server_default=None)


def downgrade() -> None:
    # Reversible but still non-destructive to unrelated data.
    if _has_column("findings", "language"):
        op.drop_column("findings", "language")
    if _has_table("users"):
        op.drop_index("ix_users_username", table_name="users")
        op.drop_table("users")
