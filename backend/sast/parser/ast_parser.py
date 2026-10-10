"""AST-based parser for Python source files.

The parser never executes the analysed code. It only builds a Python ``ast``
tree and exposes helpers (source lines, snippets, qualified call names) that the
rules and taint engine rely on.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ParsedModule:
    """Holds a parsed module together with its source for snippet extraction."""

    file_path: str
    source: str
    tree: Optional[ast.AST]
    lines: List[str] = field(default_factory=list)
    syntax_error: Optional[str] = None

    def snippet(self, line: int, context: int = 0) -> str:
        """Return the source line (1-indexed) optionally with surrounding context."""
        if not self.lines or line < 1:
            return ""
        start = max(0, line - 1 - context)
        end = min(len(self.lines), line + context)
        return "\n".join(self.lines[start:end]).strip()

    @property
    def ok(self) -> bool:
        return self.tree is not None and self.syntax_error is None


def parse_source(source: str, file_path: str = "<string>") -> ParsedModule:
    """Parse Python source text into a :class:`ParsedModule`.

    A syntax error does not raise; it is captured so the scan can continue over
    other files and still report the problem.
    """
    lines = source.splitlines()
    try:
        tree = ast.parse(source, filename=file_path)
        return ParsedModule(file_path=file_path, source=source, tree=tree, lines=lines)
    except SyntaxError as exc:  # noqa: PERF203
        return ParsedModule(
            file_path=file_path,
            source=source,
            tree=None,
            lines=lines,
            syntax_error=f"{exc.msg} (line {exc.lineno})",
        )


def parse_file(file_path: str) -> ParsedModule:
    """Read a file from disk and parse it. The file content is never executed."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    return parse_source(source, file_path=file_path)


# ----------------------------------------------------------------------------
# AST helper utilities shared by rules and taint analysis
# ----------------------------------------------------------------------------
def call_full_name(node: ast.AST) -> str:
    """Return a dotted name for a call target, e.g. ``os.system`` or ``eval``.

    Works on ``ast.Call.func`` nodes (Name / Attribute). Returns "" when it
    cannot be resolved statically.
    """
    return attr_chain(node)


def attr_chain(node: ast.AST) -> str:
    """Resolve a dotted attribute/name chain into a string.

    ``os.path.join`` -> "os.path.join"; ``request.args.get`` -> "request.args.get".
    """
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    elif isinstance(cur, ast.Call):
        # e.g. foo().bar -> resolve inner call target then append
        inner = attr_chain(cur.func)
        if inner:
            parts.append(inner + "()")
    return ".".join(reversed(parts))


def literal_str(node: ast.AST) -> Optional[str]:
    """Return the string value if ``node`` is a string constant, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def keyword_value(call: ast.Call, name: str) -> Optional[ast.AST]:
    """Return the AST value node for a keyword argument of a call, if present."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None
