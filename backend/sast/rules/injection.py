"""AST rules for injection patterns that are detectable structurally.

Deep data-flow detection (user input -> sink) is handled by the taint engine.
These rules catch obviously dangerous *shapes* even without a tracked source,
e.g. an f-string / concatenation passed straight into cursor.execute().
"""
from __future__ import annotations

import ast
from typing import List

from sast.models import Finding
from sast.parser.ast_parser import ParsedModule, attr_chain
from sast.rules.base import Rule, register
from app.core.enums import Severity


def _is_dynamic_string(node: ast.AST) -> bool:
    """True if the node builds a string dynamically (concat / f-string / %/format)."""
    if isinstance(node, ast.JoinedStr):  # f-string
        # Only dynamic if it has interpolated parts
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True
    return False


@register
class SqlStringBuildRule(Rule):
    """Flag dynamically-built strings passed to a DB execute() call."""

    rule_id = "SG007"
    title = "Potential SQL Injection (dynamic query string)"

    _EXECUTE_FUNCS = ("execute", "executemany", "executescript")

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        if not module.tree:
            return findings
        for call in self.iter_calls(module):
            if not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr not in self._EXECUTE_FUNCS:
                continue
            if not call.args:
                continue
            first = call.args[0]
            if _is_dynamic_string(first) and self._looks_like_sql(first):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            "A SQL statement is built with string concatenation / "
                            "formatting and passed to execute(). This is the classic "
                            "SQL injection pattern."
                        ),
                        file_path=module.file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        code_snippet=module.snippet(call.lineno),
                        severity=Severity.CRITICAL,
                        confidence=0.7,
                        cwe="CWE-89",
                        owasp="A03:2021 - Injection",
                        recommendation=(
                            "Use parameterized queries: cursor.execute('... WHERE "
                            "id = %s', (value,)). Never build SQL with f-strings or +."
                        ),
                        engines=["ast"],
                    )
                )
        return findings

    @staticmethod
    def _looks_like_sql(node: ast.AST) -> bool:
        """Cheap heuristic: does any string constant in the expression look like SQL?"""
        keywords = ("select ", "insert ", "update ", "delete ", "where ",
                    "from ", "drop ", "union ", "values")
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                low = sub.value.lower()
                if any(k in low for k in keywords):
                    return True
        return False
