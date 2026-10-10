"""Tests for the Security Gate policy evaluation."""
from app.services.security_gate import evaluate_gate, GatePolicy
from app.core.enums import GateStatus


def _counts(critical=0, high=0, medium=0, low=0, info=0):
    return {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium,
            "LOW": low, "INFO": info}


def test_fail_on_one_critical():
    result = evaluate_gate(_counts(critical=1))
    assert result.status == GateStatus.FAIL


def test_fail_on_three_high():
    result = evaluate_gate(_counts(high=3))
    assert result.status == GateStatus.FAIL


def test_two_high_does_not_fail_by_default():
    result = evaluate_gate(_counts(high=2))
    assert result.status != GateStatus.FAIL


def test_warning_on_medium_threshold():
    policy = GatePolicy(fail_critical=1, fail_high=3, warn_medium=5)
    result = evaluate_gate(_counts(medium=5), policy)
    assert result.status == GateStatus.WARNING


def test_pass_when_clean():
    result = evaluate_gate(_counts(low=2, info=1))
    assert result.status == GateStatus.PASS


def test_critical_takes_precedence_over_warning():
    result = evaluate_gate(_counts(critical=1, medium=10))
    assert result.status == GateStatus.FAIL


def test_reasons_present_on_fail():
    result = evaluate_gate(_counts(critical=2, high=4))
    assert any("critical" in r.lower() for r in result.reasons)
    assert any("high" in r.lower() for r in result.reasons)


def test_custom_policy_stricter_high():
    policy = GatePolicy(fail_critical=1, fail_high=1, warn_medium=5)
    result = evaluate_gate(_counts(high=1), policy)
    assert result.status == GateStatus.FAIL


def test_to_dict_shape():
    result = evaluate_gate(_counts(critical=1))
    d = result.to_dict()
    assert set(d.keys()) == {"status", "critical", "high", "medium", "low", "info", "reasons"}
