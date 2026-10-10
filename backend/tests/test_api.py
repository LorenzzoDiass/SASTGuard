"""Tests for the main API endpoints using an isolated SQLite database.

The DATABASE_URL env var is set before importing any app module so the whole
stack (config, database engine, workers) binds to the same throwaway database.
"""
import os

import pytest
from fastapi.testclient import TestClient

from app.core.database import init_db
from app.main import app

SAMPLES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable_samples")
)


@pytest.fixture(scope="module", autouse=True)
def _setup_db():
    # DATABASE_URL is set to a throwaway sqlite file in conftest.py.
    init_db()
    yield


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_create_scan_and_findings(client):
    r = client.post("/api/scans", json={"project_name": "t", "source_path": SAMPLES})
    assert r.status_code == 201
    scan = r.json()
    assert scan["status"] == "COMPLETED"
    assert scan["total_findings"] > 0

    scan_id = scan["id"]
    r = client.get(f"/api/scans/{scan_id}/findings")
    assert r.status_code == 200
    findings = r.json()
    rule_ids = {f["rule_id"] for f in findings}
    assert "TAINT-SQLI" in rule_ids  # SQL injection must be detected


def test_scan_not_found(client):
    r = client.get("/api/scans/does-not-exist")
    assert r.status_code == 404


def test_dashboard_summary(client):
    client.post("/api/scans", json={"project_name": "t", "source_path": SAMPLES})
    r = client.get("/api/dashboard/summary")
    assert r.status_code == 200
    data = r.json()
    assert data["total_vulnerabilities"] > 0
    assert data["critical"] >= 1


def test_security_gate_fail(client):
    r = client.post("/api/scans", json={"project_name": "t", "source_path": SAMPLES})
    scan_id = r.json()["id"]
    r = client.post("/api/security-gate/evaluate", json={"scan_id": scan_id})
    assert r.status_code == 200
    assert r.json()["status"] == "FAIL"


def test_ai_analysis_fallback(client):
    r = client.post("/api/scans", json={"project_name": "t", "source_path": SAMPLES})
    scan_id = r.json()["id"]
    findings = client.get(f"/api/scans/{scan_id}/findings").json()
    fid = findings[0]["id"]
    r = client.post(f"/api/findings/{fid}/ai-analysis")
    assert r.status_code == 200
    ai = r.json()["ai_analysis"]
    # Ollama is not running in CI/tests -> graceful fallback
    assert ai["available"] is False
    assert ai["explanation"] == "AI analysis unavailable"
