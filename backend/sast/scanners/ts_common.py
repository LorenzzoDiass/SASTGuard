"""Shared helpers for the Tree-sitter based JavaScript and Java scanners.

These utilities keep the per-language scanner rules small and consistent:
* secret / credential detection on string literals and assignments,
* heuristics that separate obviously-untrusted / dynamically-built arguments
  from safe constant literals (to avoid the most common false positives),
* a relative-path helper matching the other scanners.

Nothing here imports Tree-sitter directly; callers pass in a ``ParsedTree`` and
individual ``tree_sitter.Node`` objects, so this module is import-safe even when
Tree-sitter is not installed.
"""
from __future__ import annotations

import os
import re
from typing import Optional

# ---------------------------------------------------------------------------
# Secret / credential detection
# ---------------------------------------------------------------------------
# Variable/field/property names that strongly imply a secret value.
SECRET_NAME_RE = re.compile(
    r"(?:^|_|-)?(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"secret[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|"
    r"client[_-]?secret|aws[_-]?secret)(?:$|_|-)?",
    re.IGNORECASE,
)

# Values that look like placeholders / env lookups and must NOT be flagged.
_PLACEHOLDER_RE = re.compile(
    r"^(?:\s*|changeme|change_me|placeholder|example|your[_-].*|xxx+|\*+|"
    r"process\.env.*|system\.getenv.*|null|none|undefined|todo|test|dummy)$",
    re.IGNORECASE,
)

# High-entropy-ish token: long enough and mixing character classes.
_STRONG_SECRET_RE = re.compile(r"^[A-Za-z0-9+/_\-=.]{12,}$")


def looks_like_secret_name(name: str) -> bool:
    """True when an identifier name implies it stores a credential."""
    if not name:
        return False
    return bool(SECRET_NAME_RE.search(name))


def is_suspicious_secret_value(value: str) -> bool:
    """Decide whether a *string literal value* is a real hardcoded secret.

    Returns False for empty strings, obvious placeholders, environment-variable
    references and very short tokens, to keep false positives down.
    """
    if value is None:
        return False
    v = value.strip()
    if len(v) < 6:
        return False
    if _PLACEHOLDER_RE.match(v):
        return False
    # Reject values that are clearly a reference, not a literal secret.
    if v.lower().startswith(("http://", "https://", "/", "./", "../")):
        return False
    return bool(_STRONG_SECRET_RE.match(v)) or len(v) >= 8


def strip_quotes(text: str) -> str:
    """Remove surrounding single/double/back quotes from a literal's text."""
    if len(text) >= 2 and text[0] in "\"'`" and text[-1] == text[0]:
        return text[1:-1]
    return text


# ---------------------------------------------------------------------------
# Untrusted / dynamic argument heuristics
# ---------------------------------------------------------------------------
def is_pure_string_literal(node, parsed) -> bool:
    """True when a node is a single constant string literal (no interpolation).

    Used to treat ``eval("1+1")`` or ``exec("ls")`` with a constant argument as
    lower risk than dynamically built input.
    """
    if node is None:
        return False
    # JS: string / Java: string_literal. A template_string with substitutions
    # or a binary '+' concatenation is NOT a pure literal.
    if node.type in ("string", "string_literal"):
        return True
    if node.type == "template_string":
        # A template literal with no ${...} substitution is effectively constant.
        return not any(c.type == "template_substitution" for c in node.children)
    return False


def contains_concatenation(node) -> bool:
    """True when an expression builds a string via '+' concatenation.

    This is the canonical shape of SQL-injection-by-string-building in both JS
    and Java (``"SELECT ... " + userInput``).
    """
    if node is None:
        return False
    # JS: binary_expression with '+' ; Java: binary_expression with '+'.
    if node.type == "binary_expression":
        for child in node.children:
            if child.type == "+" or (child.is_named is False and child.type == "+"):
                return True
        # Fall back to operator field when available.
        op = node.child_by_field_name("operator") if hasattr(node, "child_by_field_name") else None
        if op is not None and op.type == "+":
            return True
    return False


def looks_like_sql(text: str) -> bool:
    """Heuristic: does this string look like the start/body of a SQL query?"""
    if not text:
        return False
    t = text.upper()
    keywords = ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "UNION ",
                " FROM ", " WHERE ", " VALUES", " SET ")
    return any(k in t for k in keywords)


def rel_path(path: str, base_dir: str) -> str:
    """Return a repo-relative, forward-slash path (mirrors the other scanners)."""
    if base_dir:
        try:
            return os.path.relpath(path, base_dir).replace("\\", "/")
        except ValueError:
            return path.replace("\\", "/")
    return path.replace("\\", "/")


def first_descendant_text(node, parsed, types: tuple) -> Optional[str]:
    """Return the text of the first descendant whose type is in ``types``."""
    stack = list(node.children)
    while stack:
        cur = stack.pop(0)
        if cur.type in types:
            return parsed.node_text(cur)
        stack.extend(cur.children)
    return None
