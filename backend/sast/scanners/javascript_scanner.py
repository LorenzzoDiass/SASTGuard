"""JavaScript / TypeScript security scanner (Tree-sitter based).

Implements deterministic, syntax-tree-driven rules. It consumes the shared
``treesitter_parser`` wrapper, so it degrades gracefully (``available()`` is
False and ``scan_files`` returns ``[]``) whenever Tree-sitter or its grammars
are not installed - exactly like the Bandit and Semgrep scanners.

Rules
-----
SG-JS001  eval() with a non-constant (dynamically built) argument    CRITICAL
SG-JS002  child_process.exec()/.execSync() command execution         CRITICAL/HIGH
SG-JS003  assignment to .innerHTML / .outerHTML with dynamic data     HIGH/MEDIUM
SG-JS004  SQL query built by string concatenation                     HIGH
SG-JS005  hardcoded credential / secret                               MEDIUM

Scope / honesty: this is pattern-based detection on the AST. It is **not** a
full interprocedural taint analysis for JavaScript - we do not track a value
from an HTTP request to a sink across functions. Where it matters (eval,
innerHTML) we distinguish a constant literal argument from a dynamic one to
avoid the most obvious false positives, and we say so in the limitations.
"""
from __future__ import annotations

import os
from typing import List, Optional

from sast.models import Finding
from sast.parser import treesitter_parser as ts
import sast.scanners.ts_common as C
from app.core.enums import Severity


class JavaScriptScanner:
    name = "javascript"

    # Logical languages this scanner handles.
    _LANGUAGES = {"javascript", "typescript", "tsx"}

    def available(self) -> bool:
        return ts.is_available()

    def scan_files(self, files: List[str], base_dir: str = "") -> List[Finding]:
        if not self.available():
            return []
        findings: List[Finding] = []
        for path in files:
            language = ts.language_for_extension(os.path.splitext(path)[1])
            if language not in self._LANGUAGES:
                continue
            parsed = ts.parse_file(path, language)
            if parsed is None or not parsed.ok:
                continue
            rel = C.rel_path(path, base_dir)
            for f in self._scan_tree(parsed):
                f.file_path = rel
                findings.append(f)
        return findings

    # ------------------------------------------------------------------
    # Rule driver
    # ------------------------------------------------------------------
    def _scan_tree(self, parsed) -> List[Finding]:
        findings: List[Finding] = []
        for node in parsed.walk():
            if node.type == "call_expression":
                findings.extend(self._check_call(parsed, node))
            elif node.type == "assignment_expression":
                findings.extend(self._check_innerhtml(parsed, node))
            elif node.type in ("variable_declarator", "pair",
                               "public_field_definition", "property_signature"):
                findings.extend(self._check_secret(parsed, node))
        return findings

    # ------------------------------------------------------------------
    # SG-JS001 eval / SG-JS002 child_process.exec / SG-JS004 sql concat
    # ------------------------------------------------------------------
    def _check_call(self, parsed, node) -> List[Finding]:
        out: List[Finding] = []
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is None:
            return out
        callee = parsed.node_text(func)
        callee_name = callee.split(".")[-1]
        first_arg = _first_argument(args)

        # SG-JS001: eval(...) with a dynamic argument.
        if callee == "eval" or callee_name == "eval":
            dynamic = first_arg is not None and not C.is_pure_string_literal(first_arg, parsed)
            if first_arg is None or dynamic:
                out.append(self._finding(
                    parsed, node,
                    rule_id="SG-JS001",
                    title="Code injection via eval()",
                    description=("eval() executes a dynamically built string as code. "
                                 "Untrusted input reaching eval() leads to arbitrary "
                                 "code execution."),
                    severity=Severity.CRITICAL,
                    confidence=0.8 if dynamic else 0.6,
                    cwe="CWE-95",
                    owasp="A03:2021 - Injection",
                    recommendation=("Avoid eval(). Use JSON.parse() for data, or a "
                                    "dispatch table / safe parser instead of executing "
                                    "strings."),
                ))

        # SG-JS002: child_process exec / execSync.
        if callee_name in ("exec", "execSync") and _mentions_child_process(callee, callee_name):
            dynamic = first_arg is not None and not C.is_pure_string_literal(first_arg, parsed)
            out.append(self._finding(
                parsed, node,
                rule_id="SG-JS002",
                title="OS command execution via child_process.exec()",
                description=("child_process.exec()/execSync() spawns a shell. Building "
                             "the command from untrusted input enables command "
                             "injection."),
                severity=Severity.CRITICAL if dynamic else Severity.HIGH,
                confidence=0.8 if dynamic else 0.6,
                cwe="CWE-78",
                owasp="A03:2021 - Injection",
                recommendation=("Prefer child_process.execFile()/spawn() with an "
                                "argument array and shell:false; validate/allow-list "
                                "any user input."),
            ))

        # SG-JS004: SQL built via concatenation passed to a query/execute call.
        if callee_name in ("query", "execute", "exec", "raw") and args is not None:
            if _has_sql_concatenation(args, parsed):
                out.append(self._finding(
                    parsed, node,
                    rule_id="SG-JS004",
                    title="SQL injection via string concatenation",
                    description=("A SQL statement is assembled with '+' string "
                                 "concatenation and passed to a query call. Untrusted "
                                 "values concatenated into SQL enable injection."),
                    severity=Severity.HIGH,
                    confidence=0.7,
                    cwe="CWE-89",
                    owasp="A03:2021 - Injection",
                    recommendation=("Use parameterized queries / prepared statements "
                                    "(e.g. db.query(sql, [params])) instead of "
                                    "concatenating input into the query string."),
                ))
        return out

    # ------------------------------------------------------------------
    # SG-JS003 innerHTML / outerHTML sink
    # ------------------------------------------------------------------
    def _check_innerhtml(self, parsed, node) -> List[Finding]:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None:
            return []
        left_text = parsed.node_text(left)
        prop = left_text.split(".")[-1]
        if prop not in ("innerHTML", "outerHTML"):
            return []
        # Constant string assignment is far lower risk than dynamic data.
        dynamic = right is not None and not C.is_pure_string_literal(right, parsed)
        if not dynamic:
            return []
        return [self._finding(
            parsed, node,
            rule_id="SG-JS003",
            title="DOM-based XSS via innerHTML assignment",
            description=("Assigning dynamically built data to innerHTML/outerHTML "
                         "renders it as HTML. Untrusted data here leads to cross-site "
                         "scripting (XSS)."),
            severity=Severity.HIGH,
            confidence=0.6,
            cwe="CWE-79",
            owasp="A03:2021 - Injection",
            recommendation=("Use textContent for text, or sanitize HTML with a vetted "
                            "library (e.g. DOMPurify) before assigning to innerHTML."),
        )]

    # ------------------------------------------------------------------
    # SG-JS005 hardcoded secret
    # ------------------------------------------------------------------
    def _check_secret(self, parsed, node) -> List[Finding]:
        name_node = node.child_by_field_name("name") or node.child_by_field_name("key")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None:
            return []
        if value_node.type not in ("string", "template_string"):
            return []
        name = C.strip_quotes(parsed.node_text(name_node))
        value = C.strip_quotes(parsed.node_text(value_node))
        if not C.looks_like_secret_name(name):
            return []
        if not C.is_suspicious_secret_value(value):
            return []
        return [self._finding(
            parsed, node,
            rule_id="SG-JS005",
            title="Hardcoded credential",
            description=(f"The identifier '{name}' is assigned a hardcoded secret-like "
                         "value. Credentials in source code can leak via version "
                         "control and builds."),
            severity=Severity.MEDIUM,
            confidence=0.6,
            cwe="CWE-798",
            owasp="A07:2021 - Identification and Authentication Failures",
            recommendation=("Load secrets from environment variables or a secrets "
                            "manager; never commit them to source."),
        )]

    # ------------------------------------------------------------------
    def _finding(self, parsed, node, *, rule_id, title, description, severity,
                 confidence, cwe, owasp, recommendation) -> Finding:
        line = parsed.line_of(node)
        return Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            file_path=parsed.file_path,
            line=line,
            column=parsed.column_of(node),
            code_snippet=parsed.snippet(line),
            severity=severity,
            confidence=confidence,
            cwe=cwe,
            owasp=owasp,
            recommendation=recommendation,
            engines=[self.name],
            language=parsed.language,
        )


# ----------------------------------------------------------------------------
# Node helpers
# ----------------------------------------------------------------------------
def _first_argument(args) -> Optional[object]:
    """Return the first real argument node inside an ``arguments`` node."""
    if args is None:
        return None
    for child in args.children:
        if child.type in ("(", ")", ","):
            continue
        return child
    return None


def _mentions_child_process(callee: str, callee_name: str) -> bool:
    """True when a call to exec/execSync is a child_process shell call.

    Matches ``child_process.exec(...)``, ``cp.exec(...)`` where cp is a common
    alias, and a bare ``exec(...)`` is NOT matched (too ambiguous) unless it is
    an attribute access on something. We require a member expression to reduce
    false positives on unrelated .exec() (e.g. RegExp.prototype.exec).
    """
    if "." not in callee:
        return False
    obj = callee.rsplit(".", 1)[0].split(".")[-1]
    # RegExp.exec / regex.exec is a very common safe pattern -> exclude.
    if obj.lower() in ("regex", "re", "pattern", "rx"):
        return False
    return True


def _has_sql_concatenation(args_node, parsed) -> bool:
    """True when any argument is a '+'-concatenation whose text looks like SQL."""
    for child in args_node.children:
        if child.type in ("(", ")", ","):
            continue
        if child.type == "binary_expression" and C.contains_concatenation(child):
            if C.looks_like_sql(parsed.node_text(child)):
                return True
    return False
