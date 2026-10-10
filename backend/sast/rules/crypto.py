"""Rules for weak cryptography: MD5, SHA1 and insecure random."""
from __future__ import annotations

import ast
from typing import List

from sast.models import Finding
from sast.parser.ast_parser import ParsedModule, attr_chain, literal_str
from sast.rules.base import Rule, register
from app.core.enums import Severity


def _hashlib_algo(call: ast.Call) -> str:
    """Return the hash algorithm name for a hashlib call, or ''.

    Handles hashlib.md5(), hashlib.new('md5') and `from hashlib import md5`.
    """
    name = attr_chain(call.func)
    if name in ("hashlib.md5", "md5"):
        return "md5"
    if name in ("hashlib.sha1", "sha1"):
        return "sha1"
    if name in ("hashlib.new", "new") and call.args:
        algo = literal_str(call.args[0])
        if algo:
            return algo.lower()
    return ""


@register
class Md5Rule(Rule):
    rule_id = "SG011"
    title = "Weak hash algorithm: MD5"

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        for call in self.iter_calls(module):
            if _hashlib_algo(call) == "md5":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            "MD5 is cryptographically broken and must not be used "
                            "for passwords, signatures or integrity of security data."
                        ),
                        file_path=module.file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        code_snippet=module.snippet(call.lineno),
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        cwe="CWE-327",
                        owasp="A02:2021 - Cryptographic Failures",
                        recommendation=(
                            "Use SHA-256 or stronger. For passwords use bcrypt, "
                            "scrypt or argon2."
                        ),
                        engines=["ast"],
                    )
                )
        return findings


@register
class Sha1Rule(Rule):
    rule_id = "SG012"
    title = "Weak hash algorithm: SHA1"

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        for call in self.iter_calls(module):
            if _hashlib_algo(call) == "sha1":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            "SHA1 is deprecated for security use due to practical "
                            "collision attacks."
                        ),
                        file_path=module.file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        code_snippet=module.snippet(call.lineno),
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        cwe="CWE-327",
                        owasp="A02:2021 - Cryptographic Failures",
                        recommendation="Use SHA-256 or stronger hashing algorithms.",
                        engines=["ast"],
                    )
                )
        return findings


@register
class InsecureRandomRule(Rule):
    rule_id = "SG013"
    title = "Insecure random in security context"

    _RANDOM_FUNCS = {
        "random.random", "random.randint", "random.choice", "random.randrange",
        "random.getrandbits", "random.sample", "random.shuffle", "random.uniform",
    }
    _SECURITY_HINT = (
        "token", "secret", "password", "passwd", "key", "nonce", "salt",
        "otp", "session", "csrf", "auth",
    )

    def check(self, module: ParsedModule) -> List[Finding]:
        findings: List[Finding] = []
        if not module.tree:
            return findings
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                name = attr_chain(node.value.func)
                if name in self._RANDOM_FUNCS:
                    target_names = " ".join(
                        t.id for t in node.targets if isinstance(t, ast.Name)
                    ).lower()
                    if any(h in target_names for h in self._SECURITY_HINT):
                        findings.append(self._finding(module, node.value, high=True))
            elif isinstance(node, ast.Call) and attr_chain(node.func) in self._RANDOM_FUNCS:
                # Any use of the random module is at least LOW/INFO worthy.
                findings.append(self._finding(module, node, high=False))
        return self._dedup(findings)

    def _finding(self, module: ParsedModule, call: ast.Call, high: bool) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            description=(
                "The 'random' module is not cryptographically secure. If used to "
                "generate tokens/secrets it is predictable."
            ),
            file_path=module.file_path,
            line=call.lineno,
            column=call.col_offset,
            code_snippet=module.snippet(call.lineno),
            severity=Severity.HIGH if high else Severity.LOW,
            confidence=0.8 if high else 0.4,
            cwe="CWE-330",
            owasp="A02:2021 - Cryptographic Failures",
            recommendation="Use the 'secrets' module for security-sensitive randomness.",
            engines=["ast"],
        )

    @staticmethod
    def _dedup(findings: List[Finding]) -> List[Finding]:
        seen = {}
        for f in findings:
            key = (f.line, f.column)
            # keep the higher severity one at a given location
            if key not in seen or f.severity.rank > seen[key].severity.rank:
                seen[key] = f
        return list(seen.values())
