"""Semgrep integration. Runs semgrep as a subprocess and normalizes its JSON.

Uses the project's custom ruleset under ``semgrep_rules/`` if present, and falls
back to the bundled "auto"/python registry config. Degrades gracefully when
semgrep is not installed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import List, Optional

from sast.models import Finding
from app.core.enums import Severity


_SEV_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepScanner:
    name = "semgrep"

    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path

    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan_dir(self, target_dir: str) -> List[Finding]:
        if not self.available():
            return []

        config = self._resolve_config()
        cmd = ["semgrep", "--json", "--quiet", "--config", config, target_dir]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
        except (subprocess.TimeoutExpired, OSError):
            return []

        if not proc.stdout:
            return []
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []

        findings: List[Finding] = []
        for res in data.get("results", []):
            extra = res.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            sev = _SEV_MAP.get(extra.get("severity", "WARNING"), Severity.MEDIUM)
            cwe = _first(meta.get("cwe"))
            owasp = _first(meta.get("owasp"))
            rel = _rel(res.get("path", ""), target_dir)
            findings.append(
                Finding(
                    rule_id=res.get("check_id", "semgrep"),
                    title=(meta.get("shortDescription") or res.get("check_id", "")).split(".")[-1],
                    description=extra.get("message", ""),
                    file_path=rel,
                    line=res.get("start", {}).get("line", 0),
                    column=res.get("start", {}).get("col", 0),
                    code_snippet=(extra.get("lines", "") or "").strip(),
                    severity=sev,
                    confidence=0.7,
                    cwe=_normalize_cwe(cwe),
                    owasp=owasp,
                    recommendation=meta.get("references", [""])[0] if meta.get("references") else "",
                    engines=["semgrep"],
                )
            )
        return findings

    def _resolve_config(self) -> str:
        if self.rules_path and os.path.isdir(self.rules_path):
            return self.rules_path
        # Look for the repo-level custom rules directory.
        candidate = os.path.join(os.getcwd(), "semgrep_rules")
        if os.path.isdir(candidate):
            return candidate
        # fall back to the registry python ruleset
        return "p/python"


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _normalize_cwe(cwe) -> Optional[str]:
    if not cwe:
        return None
    text = str(cwe)
    # semgrep gives e.g. "CWE-89: SQL Injection"
    if text.upper().startswith("CWE-"):
        return text.split(":")[0].strip()
    return text


def _rel(path: str, base_dir: str) -> str:
    try:
        return os.path.relpath(path, base_dir).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")
