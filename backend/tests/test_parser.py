"""Tests for the AST parser."""
from sast.parser import parse_source


def test_parses_valid_source():
    module = parse_source("x = 1\ny = x + 2\n", "a.py")
    assert module.ok
    assert module.tree is not None
    assert module.syntax_error is None


def test_captures_syntax_error_without_raising():
    module = parse_source("def broken(:\n    pass\n", "bad.py")
    assert not module.ok
    assert module.tree is None
    assert "line" in module.syntax_error.lower() or module.syntax_error


def test_snippet_returns_requested_line():
    src = "a = 1\nb = 2\nc = 3\n"
    module = parse_source(src, "a.py")
    assert module.snippet(2) == "b = 2"


def test_attr_chain_resolution():
    from sast.parser.ast_parser import attr_chain
    import ast

    tree = ast.parse("request.args.get('x')")
    call = tree.body[0].value
    assert attr_chain(call.func) == "request.args.get"
