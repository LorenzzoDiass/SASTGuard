"""Shared enumerations used across the SAST platform."""
from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Severity levels ordered from most to least critical."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank where higher means more severe (useful for sorting/merging)."""
        return {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }[self.value]

    @classmethod
    def max(cls, a: "Severity", b: "Severity") -> "Severity":
        return a if a.rank >= b.rank else b


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class GateStatus(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"


class Engine(str, Enum):
    """SAST engines that can produce findings."""

    AST = "ast"
    TAINT = "taint"
    BANDIT = "bandit"
    SEMGREP = "semgrep"
