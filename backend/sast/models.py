"""Framework-agnostic data structures produced by the SAST engine.

These are plain dataclasses (not ORM/Pydantic) so the engine can run fully
standalone (e.g. from the CLI) without any database or web dependency.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from app.core.enums import Severity


@dataclass
class TaintStep:
    """A single step in a source -> propagation -> sink chain."""

    kind: str          # "SOURCE" | "PROPAGATION" | "SINK"
    description: str
    line: int
    code: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    """A single detected vulnerability, normalized across every engine."""

    rule_id: str
    title: str
    description: str
    file_path: str
    line: int
    severity: Severity
    confidence: float = 0.5
    column: int = 0
    code_snippet: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    recommendation: str = ""
    engines: List[str] = field(default_factory=list)
    taint_path: Optional[List[TaintStep]] = None
    # Source language of the finding: "python" | "javascript" | "typescript"
    # | "java". Defaults to Python so every existing engine keeps its behaviour.
    language: str = "python"

    def dedup_key(self) -> str:
        """Stable key used to merge the same vuln reported by multiple engines.

        Keyed on normalized rule family + file + line so that AST, Bandit and
        Semgrep reporting the same issue collapse into one finding.
        """
        family = _rule_family(self.rule_id)
        raw = f"{family}:{self.file_path}:{self.line}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        if self.taint_path:
            data["taint_path"] = [s.to_dict() for s in self.taint_path]
        return data


# Map engine-specific rule ids to a shared logical family for deduplication.
_FAMILY_MAP = {
    # eval / exec
    "eval": {"SG001", "B307", "python.lang.security.audit.eval-detected.eval-detected"},
    "exec": {"SG002", "B102", "python.lang.security.audit.exec-detected.exec-detected"},
    # command execution
    "os-system": {"SG004", "B605", "python.lang.security.audit.dangerous-system-call.dangerous-system-call"},
    "subprocess-shell": {"SG003", "B602", "B603", "B604",
                          "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"},
    # crypto
    "md5": {"SG011", "B303", "B324", "python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5"},
    "sha1": {"SG012", "B303-sha1", "python.lang.security.insecure-hash-algorithms-sha1.insecure-hash-algorithm-sha1"},
    # deserialization
    "pickle": {"SG009", "B301", "B403", "python.lang.security.audit.avoid-pickle.avoid-pickle"},
    "yaml-load": {"SG010", "B506", "python.lang.security.audit.avoid-insecure-deserialization.avoid-insecure-deserialization"},
    # sql / command injection (taint + others)
    "sql-injection": {"SG007", "B608", "TAINT-SQLI",
                      "python.lang.security.audit.formatted-sql-query.formatted-sql-query"},
    "command-injection": {"SG008", "TAINT-CMDI"},
    # secrets
    "hardcoded-password": {"SG001-pw", "SECRET-PW", "B105", "B106", "B107"},
    "hardcoded-secret": {"SECRET-KEY", "generic-api-key"},
    # misc
    "requests-no-verify": {"SG014", "B501"},
    "flask-debug": {"SG015", "B201"},
    "insecure-random": {"SG013", "B311"},
    "path-traversal": {"SG016", "TAINT-PATH"},
}

# Build reverse lookup once.
_REVERSE_FAMILY = {}
for _fam, _ids in _FAMILY_MAP.items():
    for _rid in _ids:
        _REVERSE_FAMILY[_rid] = _fam


def _rule_family(rule_id: str) -> str:
    """Return a logical family for a rule id, falling back to the id itself."""
    if rule_id in _REVERSE_FAMILY:
        return _REVERSE_FAMILY[rule_id]
    # Heuristic fallback for semgrep long ids / bandit ids
    low = rule_id.lower()
    for key in ("eval", "exec", "pickle", "yaml", "md5", "sha1", "subprocess",
                "sql", "command", "password", "secret", "random", "verify",
                "debug", "traversal", "system"):
        if key in low:
            return key
    return rule_id
