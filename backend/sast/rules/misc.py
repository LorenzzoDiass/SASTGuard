"""Miscellaneous rules: requests verify=False and Flask debug=True."""
from __future__ import annotations

import ast
from typing import List

from sast.models import Finding
from sast.parser.ast_parser import ParsedModule, attr_chain, keyword_value
from sast.rules.base import Rule, register
from app.core.enums import Severity


@register
class RequestsVerifyFalseRule(Rule):
    rule_id = "SG014"
    title = "TLS verification disabled (verify=False)"

    _REQUEST_FUNCS = {
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "requests.patch", "requests.head", "requests.request",
        "session.get", "session.post", "session.request",
    }

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        for call in self.iter_calls(module):
            name = attr_chain(call.func)
            if name not in self._REQUEST_FUNCS and not name.endswith(".request"):
                if name not in self._REQUEST_FUNCS:
                    continue
            verify = keyword_value(call, "verify")
            if verify is not None and isinstance(verify, ast.Constant) and verify.value is False:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            "verify=False disables TLS certificate validation, "
                            "exposing traffic to man-in-the-middle attacks."
                        ),
                        file_path=module.file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        code_snippet=module.snippet(call.lineno),
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        cwe="CWE-295",
                        owasp="A05:2021 - Security Misconfiguration",
                        recommendation=(
                            "Keep certificate validation enabled. Provide a proper "
                            "CA bundle via verify='/path/ca.pem' if needed."
                        ),
                        engines=["ast"],
                    )
                )
        return findings


@register
class FlaskDebugRule(Rule):
    rule_id = "SG015"
    title = "Flask app run with debug=True"

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        for call in self.iter_calls(module):
            name = attr_chain(call.func)
            # app.run(...) or <something>.run(...)
            if not name.endswith(".run") and name != "run":
                continue
            debug = keyword_value(call, "debug")
            if debug is not None and isinstance(debug, ast.Constant) and debug.value is True:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            "Running Flask with debug=True enables the Werkzeug "
                            "debugger, which exposes an interactive console and "
                            "allows arbitrary code execution in production."
                        ),
                        file_path=module.file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        code_snippet=module.snippet(call.lineno),
                        severity=Severity.HIGH,
                        confidence=0.85,
                        cwe="CWE-489",
                        owasp="A05:2021 - Security Misconfiguration",
                        recommendation="Never enable debug mode in production.",
                        engines=["ast"],
                    )
                )
        return findings
