"""Scanner that runs the built-in AST rules + taint analysis over files."""
from __future__ import annotations

import os
from typing import List

from sast.models import Finding
from sast.parser.ast_parser import parse_file
from sast.rules import get_rules
from sast.taint import analyze_taint


class AstScanner:
    """Runs the native engine (AST rules + taint) on a list of Python files."""

    name = "ast"

    def scan_files(self, files: List[str], base_dir: str = "") -> List[Finding]:
        findings: List[Finding] = []
        rules = get_rules()
        for path in files:
            module = parse_file(path)
            rel = _rel(path, base_dir)
            if not module.ok:
                continue  # syntax errors are skipped; other engines may still report
            for rule in rules:
                for f in rule.check(module):
                    f.file_path = rel
                    findings.append(f)
            for f in analyze_taint(module):
                f.file_path = rel
                findings.append(f)
        return findings


def _rel(path: str, base_dir: str) -> str:
    if base_dir:
        try:
            return os.path.relpath(path, base_dir).replace("\\", "/")
        except ValueError:
            return path.replace("\\", "/")
    return path.replace("\\", "/")
