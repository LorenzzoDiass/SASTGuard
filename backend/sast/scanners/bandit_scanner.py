"""Bandit integration. Runs bandit as a subprocess and normalizes its JSON.

If bandit is not installed the scanner degrades gracefully (returns no findings
and reports availability), so the platform keeps working.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import List

from sast.models import Finding
from app.core.enums import Severity


# Bandit severity -> our Severity
_SEV_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNDEFINED": Severity.INFO,
}

_CONF_MAP = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3, "UNDEFINED": 0.5}


class BanditScanner:
    name = "bandit"

    def available(self) -> bool:
        return shutil.which("bandit") is not None

    def scan_dir(self, target_dir: str) -> List[Finding]:
        if not self.available():
            return []
        try:
            proc = subprocess.run(
                ["bandit", "-r", target_dir, "-f", "json", "-q"],
                capture_output=True,
                text=True,
                timeout=300,
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
            sev = _SEV_MAP.get(res.get("issue_severity", "MEDIUM"), Severity.MEDIUM)
            conf = _CONF_MAP.get(res.get("issue_confidence", "MEDIUM"), 0.6)
            cwe = None
            cwe_obj = res.get("issue_cwe") or {}
            if isinstance(cwe_obj, dict) and cwe_obj.get("id"):
                cwe = f"CWE-{cwe_obj['id']}"
            rel = _rel(res.get("filename", ""), target_dir)
            findings.append(
                Finding(
                    rule_id=res.get("test_id", "BANDIT"),
                    title=res.get("test_name", "Bandit finding"),
                    description=res.get("issue_text", ""),
                    file_path=rel,
                    line=res.get("line_number", 0),
                    column=res.get("col_offset", 0),
                    code_snippet=(res.get("code", "") or "").strip(),
                    severity=sev,
                    confidence=conf,
                    cwe=cwe,
                    owasp=None,
                    recommendation=res.get("more_info", ""),
                    engines=["bandit"],
                )
            )
        return findings


def _rel(path: str, base_dir: str) -> str:
    try:
        return os.path.relpath(path, base_dir).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")
