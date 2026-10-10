"""Rules for dangerous call constructs: eval, exec, os.system, subprocess shell."""
from __future__ import annotations

import ast
from typing import List

from sast.models import Finding
from sast.parser.ast_parser import (
    ParsedModule,
    attr_chain,
    keyword_value,
)
from sast.rules.base import Rule, register
from app.core.enums import Severity


@register
class EvalRule(Rule):
    rule_id = "SG001"
    title = "Use of eval()"

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        for call in self.iter_calls(module):
            if attr_chain(call.func) == "eval":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            "eval() executes arbitrary Python expressions. If any "
                            "part of its argument is attacker-controlled it leads to "
                            "remote code execution."
                        ),
                        file_path=module.file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        code_snippet=module.snippet(call.lineno),
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        cwe="CWE-95",
                        owasp="A03:2021 - Injection",
                        recommendation=(
                            "Avoid eval(). Use ast.literal_eval() for literals or "
                            "explicit parsing/dispatch tables."
                        ),
                        engines=["ast"],
                    )
                )
        return findings


@register
class ExecRule(Rule):
    rule_id = "SG002"
    title = "Use of exec()"

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        for call in self.iter_calls(module):
            if attr_chain(call.func) == "exec":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            "exec() runs arbitrary Python statements and enables "
                            "remote code execution when fed untrusted input."
                        ),
                        file_path=module.file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        code_snippet=module.snippet(call.lineno),
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        cwe="CWE-95",
                        owasp="A03:2021 - Injection",
                        recommendation="Remove exec(); redesign using safe dispatch logic.",
                        engines=["ast"],
                    )
                )
        return findings


@register
class OsSystemRule(Rule):
    rule_id = "SG004"
    title = "Use of os.system()"

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        for call in self.iter_calls(module):
            if attr_chain(call.func) in ("os.system", "system"):
                # only flag os.system (attr chain) or bare system after `from os import system`
                name = attr_chain(call.func)
                if name == "system" and not self._imports_os_system(module):
                    continue
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            "os.system() runs a command through the shell. With "
                            "untrusted input this is command injection."
                        ),
                        file_path=module.file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        code_snippet=module.snippet(call.lineno),
                        severity=Severity.HIGH,
                        confidence=0.85,
                        cwe="CWE-78",
                        owasp="A03:2021 - Injection",
                        recommendation=(
                            "Use subprocess.run([...]) with an argument list and "
                            "shell=False instead of os.system()."
                        ),
                        engines=["ast"],
                    )
                )
        return findings

    @staticmethod
    def _imports_os_system(module: ParsedModule) -> bool:
        if not module.tree:
            return False
        for node in ast.walk(module.tree):
            if isinstance(node, ast.ImportFrom) and node.module == "os":
                for alias in node.names:
                    if alias.name == "system":
                        return True
        return False


@register
class SubprocessShellRule(Rule):
    rule_id = "SG003"
    title = "subprocess call with shell=True"

    _SUBPROCESS_FUNCS = {
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
    }

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        for call in self.iter_calls(module):
            name = attr_chain(call.func)
            if name not in self._SUBPROCESS_FUNCS:
                continue
            shell_kw = keyword_value(call, "shell")
            if shell_kw is not None and isinstance(shell_kw, ast.Constant) and shell_kw.value is True:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            f"{name}(..., shell=True) runs the command through the "
                            "shell, enabling command injection when input is untrusted."
                        ),
                        file_path=module.file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        code_snippet=module.snippet(call.lineno),
                        severity=Severity.HIGH,
                        confidence=0.85,
                        cwe="CWE-78",
                        owasp="A03:2021 - Injection",
                        recommendation=(
                            "Pass the command as a list and keep shell=False "
                            "(the default), e.g. subprocess.run(['ls', path])."
                        ),
                        engines=["ast"],
                    )
                )
        return findings
