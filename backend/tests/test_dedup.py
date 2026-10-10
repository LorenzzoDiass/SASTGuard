"""Tests for finding deduplication across engines."""
from sast.engine import deduplicate
from sast.models import Finding
from app.core.enums import Severity


def _f(rule_id, file_path, line, severity, engines, confidence=0.5):
    return Finding(
        rule_id=rule_id, title=rule_id, description="", file_path=file_path,
        line=line, severity=severity, confidence=confidence, engines=list(engines),
    )


def test_same_vuln_from_multiple_engines_merges():
    findings = [
        _f("SG001", "a.py", 10, Severity.CRITICAL, ["ast"]),
        _f("B307", "a.py", 10, Severity.MEDIUM, ["bandit"]),
    ]
    merged = deduplicate(findings)
    assert len(merged) == 1
    assert set(merged[0].engines) == {"ast", "bandit"}


def test_merge_keeps_highest_severity():
    findings = [
        _f("SG011", "a.py", 5, Severity.MEDIUM, ["ast"]),
        _f("B324", "a.py", 5, Severity.HIGH, ["bandit"]),
    ]
    merged = deduplicate(findings)
    assert len(merged) == 1
    assert merged[0].severity == Severity.HIGH


def test_merge_keeps_highest_confidence():
    findings = [
        _f("SG001", "a.py", 1, Severity.CRITICAL, ["ast"], confidence=0.6),
        _f("B307", "a.py", 1, Severity.CRITICAL, ["bandit"], confidence=0.9),
    ]
    merged = deduplicate(findings)
    assert merged[0].confidence == 0.9


def test_different_lines_do_not_merge():
    findings = [
        _f("SG001", "a.py", 10, Severity.CRITICAL, ["ast"]),
        _f("SG001", "a.py", 20, Severity.CRITICAL, ["ast"]),
    ]
    merged = deduplicate(findings)
    assert len(merged) == 2


def test_different_files_do_not_merge():
    findings = [
        _f("SG001", "a.py", 10, Severity.CRITICAL, ["ast"]),
        _f("SG001", "b.py", 10, Severity.CRITICAL, ["ast"]),
    ]
    merged = deduplicate(findings)
    assert len(merged) == 2


def test_result_sorted_by_severity():
    findings = [
        _f("SG011", "a.py", 1, Severity.MEDIUM, ["ast"]),
        _f("SG001", "a.py", 2, Severity.CRITICAL, ["ast"]),
        _f("SG013", "a.py", 3, Severity.LOW, ["ast"]),
    ]
    merged = deduplicate(findings)
    severities = [f.severity for f in merged]
    assert severities == sorted(severities, key=lambda s: -s.rank)
