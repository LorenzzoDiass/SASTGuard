"""Integration test: run the full engine over the vulnerable samples."""
import os

from sast.engine import SastEngine, severity_counts

SAMPLES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable_samples")
)


def test_engine_detects_core_vulnerabilities():
    engine = SastEngine()
    # Disable external engines so the test is deterministic without bandit/semgrep.
    result = engine.scan_path(SAMPLES, use_bandit=False, use_semgrep=False)
    ids = {f.rule_id for f in result.findings}

    # At least these must be detected by the native engine alone.
    assert "SG001" in ids           # eval
    assert "SG002" in ids           # exec
    assert "TAINT-SQLI" in ids      # SQL injection (taint)
    assert "TAINT-CMDI" in ids      # command injection (taint)
    assert "TAINT-PATH" in ids      # path traversal (taint)
    assert "SG009" in ids           # pickle
    assert "SG010" in ids           # yaml.load
    assert "SG011" in ids           # md5

    counts = severity_counts(result.findings)
    assert counts["CRITICAL"] >= 3
    assert len(result.findings) >= 10


def test_safe_samples_have_no_native_findings():
    engine = SastEngine()
    safe_dir = os.path.join(SAMPLES, "safe")
    result = engine.scan_path(safe_dir, use_bandit=False, use_semgrep=False)
    # The native AST + taint engine must not flag the safe equivalents.
    assert len(result.findings) == 0
