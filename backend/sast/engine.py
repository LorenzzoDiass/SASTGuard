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
from sast.scanners import (
    AstScanner, BanditScanner, SemgrepScanner, JavaScriptScanner, JavaScanner,
)
from sast.parser import treesitter_parser as ts
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
        self.javascript_scanner = JavaScriptScanner()
        self.java_scanner = JavaScanner()

    def scan_path(self, target: str, use_bandit: bool = True,
                  use_semgrep: bool = True) -> ScanResult:
        """Scan a file or directory and return deduplicated findings.

        Python is analysed by the native AST+taint engine (plus Bandit/Semgrep
        when available). JavaScript/TypeScript and Java are analysed by the
        Tree-sitter scanners when their runtime is installed; otherwise those
        scanners report unavailable and are skipped, exactly like Bandit and
        Semgrep when their tools are missing.
        """
        if os.path.isfile(target):
            base_dir = os.path.dirname(target) or "."
            ext = os.path.splitext(target)[1].lower()
            py_files = [target] if ext == ".py" else []
            _lang = ts.language_for_extension(ext)
            js_files = [target] if _lang in ("javascript", "typescript", "tsx") else []
            java_files = [target] if _lang == "java" else []
        else:
            base_dir = target
            py_files = _collect_python_files(target)
            js_files = _collect_files(target, (".js", ".jsx", ".mjs", ".cjs",
                                               ".ts", ".tsx"))
            java_files = _collect_files(target, (".java",))

        all_findings: List[Finding] = []
        engines_run: List[str] = ["ast"]
        availability: Dict[str, bool] = {"ast": True}

        # 1) Native AST + taint engine (Python only - unchanged)
        all_findings.extend(self.ast_scanner.scan_files(py_files, base_dir=base_dir))

        # 2) Bandit (Python)
        availability["bandit"] = self.bandit_scanner.available()
        if use_bandit and availability["bandit"]:
            all_findings.extend(self.bandit_scanner.scan_dir(base_dir))
            engines_run.append("bandit")

        # 3) Semgrep (Python ruleset)
        availability["semgrep"] = self.semgrep_scanner.available()
        if use_semgrep and availability["semgrep"]:
            all_findings.extend(self.semgrep_scanner.scan_dir(base_dir))
            engines_run.append("semgrep")

        # 4) JavaScript / TypeScript (Tree-sitter)
        availability["javascript"] = self.javascript_scanner.available()
        if js_files and availability["javascript"]:
            all_findings.extend(
                self.javascript_scanner.scan_files(js_files, base_dir=base_dir)
            )
            engines_run.append("javascript")

        # 5) Java (Tree-sitter)
        availability["java"] = self.java_scanner.available()
        if java_files and availability["java"]:
            all_findings.extend(
                self.java_scanner.scan_files(java_files, base_dir=base_dir)
            )
            engines_run.append("java")

        deduped = deduplicate(all_findings)

        return ScanResult(
            findings=deduped,
            total_files=len(py_files) + len(js_files) + len(java_files),
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


_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules",
              ".pytest_cache", "dist", "build", "target", ".next", "out"}


def _collect_python_files(root: str) -> List[str]:
    files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                files.append(os.path.join(dirpath, fn))
    return files


def _collect_files(root: str, extensions: tuple) -> List[str]:
    """Collect files under ``root`` whose name ends with one of ``extensions``.

    Shares the same skip-list as the Python collector so vendored directories
    (node_modules, build output, VCS metadata) are never scanned. TypeScript
    declaration files (``.d.ts``) are intentionally excluded - they contain no
    executable code.
    """
    files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".d.ts"):
                continue
            if fn.endswith(extensions):
                files.append(os.path.join(dirpath, fn))
    return files


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
