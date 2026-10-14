"""Shared pytest fixtures."""
import os
import sys
import tempfile

# Bind the whole test session to a throwaway SQLite DB BEFORE any app module
# imports app.core.config (which caches settings). conftest is imported first.
_TEST_DB = os.path.join(tempfile.gettempdir(), "sastguard_test.db")
if os.path.exists(_TEST_DB):
    os.remove(_TEST_DB)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB.replace(os.sep, '/')}")

# The API-level tests exercise the endpoints' domain behaviour, not auth. Default
# the test session to auth-disabled so those tests keep hitting the API directly.
# The dedicated auth test module overrides this per-test to validate the real
# JWT flow (login/protection/logout).
os.environ.setdefault("AUTH_ENABLED", "false")

import pytest

# Ensure the backend package root is importable when running pytest from repo root.
BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)


@pytest.fixture()
def parse():
    from sast.parser import parse_source

    def _parse(src: str, name: str = "test.py"):
        return parse_source(src, name)

    return _parse


@pytest.fixture()
def run_rules():
    """Return a helper that runs all AST rules and returns findings."""
    from sast.rules import get_rules
    from sast.parser import parse_source

    def _run(src: str):
        module = parse_source(src, "test.py")
        findings = []
        for rule in get_rules():
            findings.extend(rule.check(module))
        return findings

    return _run


@pytest.fixture()
def run_taint():
    from sast.taint import analyze_taint
    from sast.parser import parse_source

    def _run(src: str):
        return analyze_taint(parse_source(src, "test.py"))

    return _run


def rule_ids(findings):
    return {f.rule_id for f in findings}
