"""Java security scanner (Tree-sitter based).

Deterministic, syntax-tree-driven rules consuming the shared
``treesitter_parser`` wrapper. Degrades gracefully (``available()`` is False and
``scan_files`` returns ``[]``) when Tree-sitter or the Java grammar is not
installed, matching the Bandit/Semgrep scanner behaviour.

Rules
-----
SG-JAVA001  Runtime.getRuntime().exec() / ProcessBuilder command execution  CRITICAL/HIGH
SG-JAVA002  SQL query built by string concatenation (Statement.execute*)     HIGH
SG-JAVA003  Insecure deserialization (ObjectInputStream.readObject)          CRITICAL
SG-JAVA004  Weak hash: MessageDigest.getInstance("MD5"|"SHA-1")              MEDIUM
SG-JAVA005  Hardcoded credential / secret                                    MEDIUM

Scope / honesty: pattern-based detection on the AST. It is **not** a full
interprocedural taint analysis for Java - we do not track a value from an HTTP
request parameter to a sink across methods/classes. We distinguish concatenated
SQL from parameterized queries and constant from dynamic arguments where
possible to limit obvious false positives.

Java grammar notes (tree-sitter-java):
* method_invocation has fields ``object``, ``name`` and ``arguments``
  (``arguments`` is an ``argument_list`` node).
* binary_expression exposes an ``operator`` field.
* string literals are ``string_literal`` nodes.
"""
from __future__ import annotations

import os
from typing import List, Optional

from sast.models import Finding
from sast.parser import treesitter_parser as ts
import sast.scanners.ts_common as C
from app.core.enums import Severity


class JavaScanner:
    name = "java"

    def available(self) -> bool:
        return ts.is_available()

    def scan_files(self, files: List[str], base_dir: str = "") -> List[Finding]:
        if not self.available():
            return []
        findings: List[Finding] = []
        for path in files:
            if ts.language_for_extension(os.path.splitext(path)[1]) != "java":
                continue
            parsed = ts.parse_file(path, "java")
            if parsed is None or not parsed.ok:
                continue
            rel = C.rel_path(path, base_dir)
            for f in self._scan_tree(parsed):
                f.file_path = rel
                findings.append(f)
        return findings

    # ------------------------------------------------------------------
    def _scan_tree(self, parsed) -> List[Finding]:
        findings: List[Finding] = []
        for node in parsed.walk():
            if node.type == "method_invocation":
                findings.extend(self._check_invocation(parsed, node))
            elif node.type in ("local_variable_declaration", "field_declaration"):
                findings.extend(self._check_secret(parsed, node))
        return findings

    # ------------------------------------------------------------------
    # Method-invocation rules
    # ------------------------------------------------------------------
    def _check_invocation(self, parsed, node) -> List[Finding]:
        out: List[Finding] = []
        name_node = node.child_by_field_name("name")
        obj_node = node.child_by_field_name("object")
        args_node = node.child_by_field_name("arguments")
        if name_node is None:
            return out
        method = parsed.node_text(name_node)
        obj_text = parsed.node_text(obj_node) if obj_node is not None else ""

        # SG-JAVA001: Runtime.exec(...)
        if method == "exec" and "getRuntime()" in obj_text:
            dynamic = _args_are_dynamic(args_node, parsed)
            out.append(self._finding(
                parsed, node,
                rule_id="SG-JAVA001",
                title="OS command execution via Runtime.exec()",
                description=("Runtime.getRuntime().exec() runs an external command. "
                             "Building the command from untrusted input enables "
                             "command injection."),
                severity=Severity.CRITICAL if dynamic else Severity.HIGH,
                confidence=0.8 if dynamic else 0.6,
                cwe="CWE-78",
                owasp="A03:2021 - Injection",
                recommendation=("Avoid shell execution with concatenated input. Pass an "
                                "argument array, validate/allow-list inputs, and prefer "
                                "safer APIs."),
            ))

        # SG-JAVA002: SQL via concatenation to Statement.execute*/prepareStatement
        if method in ("executeQuery", "executeUpdate", "execute",
                      "prepareStatement", "prepareCall", "addBatch"):
            if _args_have_sql_concatenation(args_node, parsed):
                out.append(self._finding(
                    parsed, node,
                    rule_id="SG-JAVA002",
                    title="SQL injection via string concatenation",
                    description=("A SQL statement is assembled with '+' concatenation and "
                                 "passed to a JDBC execute/prepare call. Concatenated "
                                 "untrusted values enable SQL injection."),
                    severity=Severity.HIGH,
                    confidence=0.75,
                    cwe="CWE-89",
                    owasp="A03:2021 - Injection",
                    recommendation=("Use PreparedStatement with bound '?' parameters; never "
                                    "concatenate input into the SQL text."),
                ))

        # SG-JAVA003: Insecure deserialization via ObjectInputStream.readObject()
        if method == "readObject" and _is_object_input_stream(obj_text):
            out.append(self._finding(
                parsed, node,
                rule_id="SG-JAVA003",
                title="Insecure deserialization (ObjectInputStream.readObject)",
                description=("Deserializing untrusted data with ObjectInputStream can "
                             "trigger gadget chains and remote code execution."),
                severity=Severity.CRITICAL,
                confidence=0.7,
                cwe="CWE-502",
                owasp="A08:2021 - Software and Data Integrity Failures",
                recommendation=("Avoid Java native serialization for untrusted data. Use a "
                                "safe data format (JSON) with a strict schema, or enforce "
                                "an allow-list via ObjectInputFilter."),
            ))

        # SG-JAVA004: Weak hash via MessageDigest.getInstance("MD5"/"SHA-1")
        if method == "getInstance" and obj_text == "MessageDigest":
            algo = _first_string_arg(args_node, parsed)
            if algo and algo.strip().upper().replace("_", "-") in ("MD5", "SHA-1", "SHA1"):
                out.append(self._finding(
                    parsed, node,
                    rule_id="SG-JAVA004",
                    title=f"Weak hash algorithm ({algo.strip()})",
                    description=("MD5 and SHA-1 are cryptographically broken and must not "
                                 "be used for security (passwords, signatures, integrity)."),
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    cwe="CWE-327",
                    owasp="A02:2021 - Cryptographic Failures",
                    recommendation=("Use SHA-256 or stronger; for passwords use a dedicated "
                                    "KDF such as bcrypt, scrypt, PBKDF2 or Argon2."),
                ))
        return out

    # ------------------------------------------------------------------
    # SG-JAVA005: hardcoded secret in a variable/field declaration
    # ------------------------------------------------------------------
    def _check_secret(self, parsed, node) -> List[Finding]:
        out: List[Finding] = []
        for declarator in node.children:
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            value_node = declarator.child_by_field_name("value")
            if name_node is None or value_node is None:
                continue
            if value_node.type != "string_literal":
                continue
            name = parsed.node_text(name_node)
            value = C.strip_quotes(parsed.node_text(value_node))
            if not C.looks_like_secret_name(name):
                continue
            if not C.is_suspicious_secret_value(value):
                continue
            out.append(self._finding(
                parsed, declarator,
                rule_id="SG-JAVA005",
                title="Hardcoded credential",
                description=(f"The field '{name}' is assigned a hardcoded secret-like "
                             "value. Credentials in source code can leak through version "
                             "control and compiled artifacts."),
                severity=Severity.MEDIUM,
                confidence=0.6,
                cwe="CWE-798",
                owasp="A07:2021 - Identification and Authentication Failures",
                recommendation=("Load secrets from environment variables, a properties file "
                                "outside VCS, or a secrets manager."),
            ))
        return out

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
def _iter_args(args_node):
    """Yield the real argument nodes inside a Java ``argument_list``."""
    if args_node is None:
        return
    for child in args_node.children:
        if child.type in ("(", ")", ","):
            continue
        yield child


def _args_are_dynamic(args_node, parsed) -> bool:
    """True when any argument is not a plain constant string literal."""
    saw_arg = False
    for arg in _iter_args(args_node):
        saw_arg = True
        if arg.type != "string_literal":
            return True
    # No args at all -> treat as not-clearly-constant.
    return not saw_arg


def _args_have_sql_concatenation(args_node, parsed) -> bool:
    for arg in _iter_args(args_node):
        if arg.type == "binary_expression" and C.contains_concatenation(arg):
            if C.looks_like_sql(parsed.node_text(arg)):
                return True
    return False


def _first_string_arg(args_node, parsed) -> Optional[str]:
    for arg in _iter_args(args_node):
        if arg.type == "string_literal":
            return C.strip_quotes(parsed.node_text(arg))
    return None


def _is_object_input_stream(obj_text: str) -> bool:
    """Heuristic: the receiver of readObject looks like an ObjectInputStream.

    Matches explicit ``new ObjectInputStream(...)`` receivers and variables whose
    name hints at an object input stream, to reduce false positives on unrelated
    ``readObject`` methods.
    """
    if not obj_text:
        return False
    t = obj_text.lower()
    return ("objectinputstream" in t) or t.endswith("ois") or "ois." in t or t == "in"
