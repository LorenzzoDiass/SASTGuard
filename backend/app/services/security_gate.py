"""Security Gate policy evaluation (pure, reusable by API and CLI).

Default policy:
    FAIL    when >= 1 CRITICAL  OR  >= 3 HIGH
    WARNING when the MEDIUM count reaches the configured threshold
    PASS    otherwise
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from app.core.config import settings
from app.core.enums import GateStatus, Severity


@dataclass
class GatePolicy:
    fail_critical: int = settings.gate_fail_critical
    fail_high: int = settings.gate_fail_high
    warn_medium: int = settings.gate_warn_medium

    def to_dict(self) -> dict:
        return {
            "fail_critical": self.fail_critical,
            "fail_high": self.fail_high,
            "warn_medium": self.warn_medium,
        }


@dataclass
class GateEvaluation:
    status: GateStatus
    critical: int
    high: int
    medium: int
    low: int
    info: int
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "reasons": self.reasons,
        }


def evaluate_gate(counts: Dict[str, int], policy: GatePolicy = None) -> GateEvaluation:
    """Evaluate the gate given severity counts.

    ``counts`` keys are severity names (CRITICAL/HIGH/MEDIUM/LOW/INFO).
    """
    policy = policy or GatePolicy()
    critical = counts.get(Severity.CRITICAL.value, 0)
    high = counts.get(Severity.HIGH.value, 0)
    medium = counts.get(Severity.MEDIUM.value, 0)
    low = counts.get(Severity.LOW.value, 0)
    info = counts.get(Severity.INFO.value, 0)

    reasons: List[str] = []
    status = GateStatus.PASS

    if policy.fail_critical > 0 and critical >= policy.fail_critical:
        status = GateStatus.FAIL
        reasons.append(f"{critical} critical vulnerabilit{_pl(critical)} detected "
                       f"(threshold {policy.fail_critical})")
    if policy.fail_high > 0 and high >= policy.fail_high:
        status = GateStatus.FAIL
        reasons.append(f"{high} high vulnerabilit{_pl(high)} detected "
                       f"(threshold {policy.fail_high})")

    if status != GateStatus.FAIL and policy.warn_medium > 0 and medium >= policy.warn_medium:
        status = GateStatus.WARNING
        reasons.append(f"{medium} medium vulnerabilit{_pl(medium)} detected "
                       f"(warning threshold {policy.warn_medium})")

    if not reasons:
        reasons.append("No blocking vulnerabilities found")

    return GateEvaluation(
        status=status, critical=critical, high=high, medium=medium,
        low=low, info=info, reasons=reasons,
    )


def _pl(n: int) -> str:
    return "y" if n == 1 else "ies"
