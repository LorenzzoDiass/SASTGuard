"""SAST orchestration engine.

Combines the native AST+taint scanner with Bandit and Semgrep, normalizes all
results into a single Finding model, and deduplicates issues reported by more
than one engine (recording which engines flagged each one).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sast.models import Finding
from sast.scanners import AstScanner, BanditScanner, SemgrepScanner
from app.core.enums import Severity


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    total_files: int = 0
    engines_run: List[str] = field(default_factory=list)
    engines_available: Dict[str, bool] = field(default_factory=dict)


class SastEngine:
    def __init__(self, semgrep_rules_path: Optional[str] = None):
        self.ast_scanner = AstScanner()
        self.bandit_scanner = BanditScanner()
        self.semgrep_scanner = SemgrepScanner(rules_path=semgrep_rules_path)

    def scan_path(self, target: str, use_bandit: bool = True,
                  use_semgrep: bool = True) -> ScanResult:
        """Scan a file or directory and return deduplicated findings."""
        if os.path.isfile(target):
            base_dir = os.path.dirname(target) or "."
            py_files = [target] if target.endswith(".py") else []
        else:
            base_dir = target
            py_files = _collect_python_files(target)

        all_findings: List[Finding] = []
        engines_run: List[str] = ["ast"]
        availability: Dict[str, bool] = {"ast": True}

        # 1) Native AST + taint engine
        all_findings.extend(self.ast_scanner.scan_files(py_files, base_dir=base_dir))

        # 2) Bandit
        availability["bandit"] = self.bandit_scanner.available()
        if use_bandit and availability["bandit"]:
            all_findings.extend(self.bandit_scanner.scan_dir(base_dir))
            engines_run.append("bandit")

        # 3) Semgrep
        availability["semgrep"] = self.semgrep_scanner.available()
        if use_semgrep and availability["semgrep"]:
            all_findings.extend(self.semgrep_scanner.scan_dir(base_dir))
            engines_run.append("semgrep")

        deduped = deduplicate(all_findings)

        return ScanResult(
            findings=deduped,
            total_files=len(py_files),
            engines_run=engines_run,
            engines_available=availability,
        )


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """Merge findings that refer to the same vulnerability.

    Two findings merge when their dedup_key (logical rule family + file + line)
    matches. The merged finding keeps the highest severity and confidence and
    accumulates the set of engines that reported it. A taint_path is preserved
    if any contributing finding had one.
    """
    merged: Dict[str, Finding] = {}
    for f in findings:
        key = f.dedup_key()
        if key not in merged:
            # copy engines list to avoid aliasing
            f.engines = list(dict.fromkeys(f.engines))
            merged[key] = f
            continue

        existing = merged[key]
        # accumulate engines
        existing.engines = list(dict.fromkeys(existing.engines + f.engines))
        # keep strongest severity
        if f.severity.rank > existing.severity.rank:
            existing.severity = f.severity
        # keep highest confidence
        existing.confidence = max(existing.confidence, f.confidence)
        # prefer having a taint path and richer metadata
        if f.taint_path and not existing.taint_path:
            existing.taint_path = f.taint_path
        if not existing.cwe and f.cwe:
            existing.cwe = f.cwe
        if not existing.owasp and f.owasp:
            existing.owasp = f.owasp
        if not existing.recommendation and f.recommendation:
            existing.recommendation = f.recommendation

    result = list(merged.values())
    result.sort(key=lambda x: (-x.severity.rank, x.file_path, x.line))
    return result


def _collect_python_files(root: str) -> List[str]:
    files: List[str] = []
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            if fn.endswith(".py"):
                files.append(os.path.join(dirpath, fn))
    return files


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
