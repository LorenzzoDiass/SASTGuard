"""Tree-sitter based parser wrapper for non-Python languages (JS/TS/Java).

The native Python engine uses the standard-library ``ast`` module (see
``ast_parser.py``) and is intentionally left untouched. This module adds *real*
syntax-tree parsing for JavaScript, TypeScript and Java using Tree-sitter.

Design goals
------------
* **Graceful degradation.** Tree-sitter and its grammars are heavy, prebuilt
  dependencies that are installed only in Docker/CI (see
  ``requirements-sast.txt``). When they are not importable, this module reports
  ``is_available() == False`` and the scanners that rely on it return no
  findings instead of crashing - mirroring how the Bandit/Semgrep scanners
  behave when their tools are missing.
* **No execution of analysed code.** We only parse source text into a syntax
  tree and walk nodes; nothing from the scanned project is ever imported or
  executed.
* **One shared tree model.** Parsers return a :class:`ParsedTree` that the
  JavaScript and Java scanners consume through small, well-defined helpers,
  keeping the scanner rule code readable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterator, List, Optional, Tuple

# Tree-sitter is an optional dependency. Importing lazily and tolerantly keeps
# the whole platform working on environments where it is not installed.
try:  # pragma: no cover - exercised indirectly via is_available()
    from tree_sitter_language_pack import get_parser as _get_ts_parser

    _IMPORT_ERROR: Optional[str] = None
except Exception as exc:  # noqa: BLE001 - any import failure disables the feature
    _get_ts_parser = None  # type: ignore[assignment]
    _IMPORT_ERROR = str(exc)


# Logical language name -> tree-sitter-language-pack grammar name.
# ``.ts``/``.tsx`` use their dedicated grammars; everything else maps to JS/Java.
_GRAMMAR_BY_LANGUAGE = {
    "javascript": "javascript",
    "typescript": "typescript",
    "tsx": "tsx",
    "java": "java",
}

# File extension -> logical language.
_LANGUAGE_BY_EXT = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
}


def is_available() -> bool:
    """Return True when the Tree-sitter runtime and grammars can be loaded."""
    return _get_ts_parser is not None


def import_error() -> Optional[str]:
    """Return the import error message when Tree-sitter is unavailable."""
    return _IMPORT_ERROR


def language_for_extension(ext: str) -> Optional[str]:
    """Map a file extension (``.js``, ``.java`` ...) to a logical language."""
    return _LANGUAGE_BY_EXT.get(ext.lower())


def supported_extensions() -> Tuple[str, ...]:
    """Return the file extensions this parser can handle."""
    return tuple(_LANGUAGE_BY_EXT.keys())


@lru_cache(maxsize=None)
def _parser_for(language: str):
    """Return a cached Tree-sitter parser for a logical language, or None."""
    if _get_ts_parser is None:
        return None
    grammar = _GRAMMAR_BY_LANGUAGE.get(language)
    if grammar is None:
        return None
    try:
        return _get_ts_parser(grammar)
    except Exception:  # noqa: BLE001 - missing grammar -> feature disabled
        return None


@dataclass
class ParsedTree:
    """A parsed source file together with helpers for rule authoring.

    ``root`` is a ``tree_sitter.Node``. We keep the raw ``source`` bytes so we
    can slice exact node text and compute 1-indexed line/column positions.
    """

    file_path: str
    language: str
    source: bytes
    root: object  # tree_sitter.Node (kept untyped to avoid a hard import)
    syntax_error: Optional[str] = None
    lines: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.root is not None

    # -- text / position helpers -------------------------------------------
    def node_text(self, node) -> str:
        """Return the exact source text covered by ``node``."""
        try:
            return self.source[node.start_byte:node.end_byte].decode(
                "utf-8", errors="replace"
            )
        except Exception:  # noqa: BLE001 - defensive
            return ""

    def line_of(self, node) -> int:
        """1-indexed start line of a node (Tree-sitter rows are 0-indexed)."""
        return node.start_point[0] + 1

    def column_of(self, node) -> int:
        """1-indexed start column of a node."""
        return node.start_point[1] + 1

    def snippet(self, line: int) -> str:
        """Return the source line (1-indexed), trimmed, for a finding."""
        if not self.lines or line < 1 or line > len(self.lines):
            return ""
        return self.lines[line - 1].strip()

    # -- traversal helpers --------------------------------------------------
    def walk(self) -> Iterator[object]:
        """Yield every node in the tree (depth-first, pre-order)."""
        if self.root is None:
            return
        stack = [self.root]
        while stack:
            node = stack.pop()
            yield node
            # push children in reverse so traversal is left-to-right
            stack.extend(reversed(node.children))

    def nodes_of_type(self, *types: str) -> Iterator[object]:
        """Yield every node whose ``type`` is one of ``types``."""
        wanted = set(types)
        for node in self.walk():
            if node.type in wanted:
                yield node


def parse_source(source: str, file_path: str, language: str) -> Optional[ParsedTree]:
    """Parse ``source`` for a logical language into a :class:`ParsedTree`.

    Returns ``None`` when Tree-sitter is unavailable or the language has no
    grammar. A syntax error does not raise: Tree-sitter is error-tolerant and
    still produces a (partial) tree, which we return with ``syntax_error`` set
    when the root reports errors.
    """
    parser = _parser_for(language)
    if parser is None:
        return None

    src_bytes = source.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(src_bytes)
    except Exception as exc:  # noqa: BLE001 - never crash the whole scan
        return ParsedTree(
            file_path=file_path,
            language=language,
            source=src_bytes,
            root=None,
            syntax_error=str(exc),
            lines=source.splitlines(),
        )

    root = tree.root_node
    syntax_error = None
    # ``has_error`` flags syntactically invalid input; we still scan what parsed.
    if getattr(root, "has_error", False):
        syntax_error = "syntax errors present (partial tree)"

    return ParsedTree(
        file_path=file_path,
        language=language,
        source=src_bytes,
        root=root,
        syntax_error=syntax_error,
        lines=source.splitlines(),
    )


def parse_file(file_path: str, language: str) -> Optional[ParsedTree]:
    """Read a file from disk and parse it. The file is never executed."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    return parse_source(source, file_path=file_path, language=language)
