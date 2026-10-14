"""Authentication tests.

Covers password hashing, JWT round-trip, the login endpoint, route protection
when auth is enabled, and the auth-disabled bypass. Requires the optional crypto
deps (``passlib[bcrypt]`` + ``python-jose``); the module is skipped when they are
not installed, and runs fully in CI / Docker where they are.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("passlib", reason="passlib not installed (CI/Docker only)")
pytest.importorskip("jose", reason="python-jose not installed (CI/Docker only)")

from app.core import security
from app.core.config import settings
from app.core.database import init_db, SessionLocal
from app.main import app
from app.models import User
from app.repositories import UserRepository


@pytest.fixture(scope="module", autouse=True)
def _setup_db():
    init_db()
    yield


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth_enabled():
    """Enable auth for the duration of a test (restored afterwards)."""
    original = settings.auth_enabled
    settings.auth_enabled = True
    yield
    settings.auth_enabled = original


@pytest.fixture()
def test_user():
    """Create a known user and return (username, password)."""
    db = SessionLocal()
    try:
        repo = UserRepository(db)
        username = "pytest_user"
        if repo.get_by_username(username) is None:
            repo.create(username=username,
                        password_hash=security.hash_password("S3cret-pass!"),
                        is_admin=False)
    finally:
        db.close()
    return "pytest_user", "S3cret-pass!"


# --- primitives -----------------------------------------------------------
def test_password_hash_roundtrip():
    h = security.hash_password("hunter2")
    assert h != "hunter2"
    assert security.verify_password("hunter2", h)
    assert not security.verify_password("wrong", h)


def test_jwt_roundtrip():
    token = security.create_access_token("uid-1", "alice", True)
    payload = security.decode_access_token(token)
    assert payload["sub"] == "uid-1"
    assert payload["username"] == "alice"
    assert payload["is_admin"] is True


def test_decode_invalid_token_returns_none():
    assert security.decode_access_token("not-a-token") is None


# --- login endpoint -------------------------------------------------------
def test_login_success_and_me(client, test_user, auth_enabled):
    username, password = test_user
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["username"] == username
    token = body["access_token"]

    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == username


def test_login_wrong_password(client, test_user, auth_enabled):
    username, _ = test_user
    r = client.post("/api/auth/login", json={"username": username, "password": "nope"})
    assert r.status_code == 401


# --- route protection -----------------------------------------------------
def test_protected_route_requires_token(client, auth_enabled):
    r = client.get("/api/dashboard/summary")
    assert r.status_code == 401


def test_protected_route_with_token(client, test_user, auth_enabled):
    username, password = test_user
    token = client.post("/api/auth/login",
                        json={"username": username, "password": password}).json()["access_token"]
    r = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_public_routes_open_even_with_auth(client, auth_enabled):
    assert client.get("/health").status_code == 200


def test_logout_endpoint(client, test_user, auth_enabled):
    username, password = test_user
    token = client.post("/api/auth/login",
                        json={"username": username, "password": password}).json()["access_token"]
    r = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


# --- auth-disabled bypass -------------------------------------------------
def test_auth_disabled_allows_access(client):
    # settings.auth_enabled defaults to False in the test session (conftest).
    assert settings.auth_enabled is False
    assert client.get("/api/dashboard/summary").status_code == 200
