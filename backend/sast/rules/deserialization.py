"""Rules for insecure deserialization: pickle and yaml.load."""
from __future__ import annotations

import ast
from typing import List

from sast.models import Finding
from sast.parser.ast_parser import ParsedModule, attr_chain, keyword_value
from sast.rules.base import Rule, register
from app.core.enums import Severity


@register
class PickleRule(Rule):
    rule_id = "SG009"
    title = "Insecure deserialization with pickle"

    _FUNCS = {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
              "_pickle.load", "_pickle.loads"}

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        for call in self.iter_calls(module):
            if attr_chain(call.func) in self._FUNCS:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            "pickle can execute arbitrary code during "
                            "deserialization. Loading untrusted pickle data is RCE."
                        ),
                        file_path=module.file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        code_snippet=module.snippet(call.lineno),
                        severity=Severity.HIGH,
                        confidence=0.8,
                        cwe="CWE-502",
                        owasp="A08:2021 - Software and Data Integrity Failures",
                        recommendation=(
                            "Never unpickle untrusted data. Use JSON or another "
                            "safe format for interchange."
                        ),
                        engines=["ast"],
                    )
                )
        return findings


@register
class YamlLoadRule(Rule):
    rule_id = "SG010"
    title = "Insecure yaml.load without SafeLoader"

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        for call in self.iter_calls(module):
            name = attr_chain(call.func)
            if name not in ("yaml.load", "load"):
                continue
            if name == "load" and not self._imports_yaml_load(module):
                continue
            if self._is_safe_loader(call):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        "yaml.load() with the default FullLoader/Loader can "
                        "instantiate arbitrary Python objects from untrusted YAML."
                    ),
                    file_path=module.file_path,
                    line=call.lineno,
                    column=call.col_offset,
                    code_snippet=module.snippet(call.lineno),
                    severity=Severity.HIGH,
                    confidence=0.8,
                    cwe="CWE-502",
                    owasp="A08:2021 - Software and Data Integrity Failures",
                    recommendation="Use yaml.safe_load() or Loader=yaml.SafeLoader.",
                    engines=["ast"],
                )
            )
        return findings

    @staticmethod
    def _is_safe_loader(call: ast.Call) -> bool:
        loader = keyword_value(call, "Loader")
        if loader is None and len(call.args) >= 2:
            loader = call.args[1]
        if loader is None:
            return False  # default loader is unsafe
        name = attr_chain(loader)
        return "SafeLoader" in name or "CSafeLoader" in name

    @staticmethod
    def _imports_yaml_load(module: ParsedModule) -> bool:
        if not module.tree:
            return False
        for node in ast.walk(module.tree):
            if isinstance(node, ast.ImportFrom) and node.module == "yaml":
                for alias in node.names:
                    if alias.name == "load":
                        return True
        return False
