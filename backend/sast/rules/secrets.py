"""Rules for hardcoded secrets: passwords and API keys/tokens.

Uses AST assignment context (variable name + string literal value) rather than
blind regex over the whole file, which drastically cuts false positives.
"""
from __future__ import annotations

import ast
import re
from typing import List

from sast.models import Finding
from sast.parser.ast_parser import ParsedModule, literal_str
from sast.rules.base import Rule, register
from app.core.enums import Severity


_PASSWORD_NAMES = re.compile(
    r"(pass|passwd|pwd|secret|token|apikey|api_key|access_key|"
    r"secret_key|private_key|auth)", re.IGNORECASE
)

# High-entropy / provider-shaped tokens.
_KEY_VALUE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),               # AWS access key id
    re.compile(r"sk-[A-Za-z0-9]{20,}"),            # OpenAI-style
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),           # GitHub PAT
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),   # Slack
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),        # Google API key
]

_PLACEHOLDER = re.compile(
    r"^(|changeme|change_me|your[-_ ]?|example|placeholder|xxx+|<.*>|\$\{.*\}|os\.environ.*)$",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    v = value.strip()
    if not v:
        return True
    if _PLACEHOLDER.match(v):
        return True
    return False


@register
class HardcodedPasswordRule(Rule):
    rule_id = "SG001-pw"
    title = "Hardcoded password"

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        if not module.tree:
            return findings
        for node in ast.walk(module.tree):
            targets = []
            value = None
            if isinstance(node, ast.Assign):
                targets = node.targets
                value = node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets = [node.target]
                value = node.value
            else:
                continue

            str_val = literal_str(value)
            if str_val is None or _is_placeholder(str_val):
                continue
            if len(str_val) < 4:
                continue

            for tgt in targets:
                name = tgt.id if isinstance(tgt, ast.Name) else getattr(tgt, "attr", "")
                if name and _PASSWORD_NAMES.search(name):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=(
                                f"Variable '{name}' is assigned a hardcoded secret "
                                "literal. Secrets in source are exposed in VCS history."
                            ),
                            file_path=module.file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=module.snippet(node.lineno),
                            severity=Severity.HIGH,
                            confidence=0.75,
                            cwe="CWE-798",
                            owasp="A07:2021 - Identification and Authentication Failures",
                            recommendation=(
                                "Load secrets from environment variables or a secrets "
                                "manager (e.g. os.environ, Vault). Never commit them."
                            ),
                            engines=["ast"],
                        )
                    )
        return findings


@register
class HardcodedApiKeyRule(Rule):
    rule_id = "SECRET-KEY"
    title = "Hardcoded API key / token"

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        if not module.tree:
            return findings
        for node in ast.walk(module.tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            value = node.value
            for pattern in _KEY_VALUE_PATTERNS:
                if pattern.search(value):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=(
                                "A string matching a known API key/token format is "
                                "embedded in source code."
                            ),
                            file_path=module.file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=module.snippet(node.lineno),
                            severity=Severity.CRITICAL,
                            confidence=0.85,
                            cwe="CWE-798",
                            owasp="A07:2021 - Identification and Authentication Failures",
                            recommendation=(
                                "Revoke the exposed credential and load it from a "
                                "secret store or environment variable."
                            ),
                            engines=["ast"],
                        )
                    )
                    break
        return findings
