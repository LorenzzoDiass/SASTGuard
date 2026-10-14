"""Tests for the Tree-sitter JavaScript and Java scanners.

These tests require the optional Tree-sitter runtime and grammars
(``tree-sitter`` + ``tree-sitter-language-pack``), which are installed only in
Docker / CI (see ``requirements-sast.txt``). When those libraries are not
present the whole module is skipped, so the suite still passes on a developer
machine that cannot install them.

They assert three things required of a real multi-language SAST capability:
1. each language scanner detects its intended vulnerability classes,
2. the safe equivalents produce none of those findings (false-positive guard),
3. a mixed Python + JavaScript + Java project yields findings for all three
   languages through the single ``SastEngine`` entry point, and those findings
   reach the Security Gate.
"""
import os

import pytest

# Skip the entire module unless the Tree-sitter stack is importable.
pytest.importorskip("tree_sitter", reason="tree-sitter not installed (CI/Docker only)")
pytest.importorskip(
    "tree_sitter_language_pack",
    reason="tree-sitter-language-pack not installed (CI/Docker only)",
)

from sast.parser import treesitter_parser as ts
from sast.scanners.javascript_scanner import JavaScriptScanner
from sast.scanners.java_scanner import JavaScanner
from sast.engine import SastEngine, severity_counts
from app.services.security_gate import evaluate_gate

SAMPLES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable_samples")
)
JS_DIR = os.path.join(SAMPLES, "javascript")
JAVA_DIR = os.path.join(SAMPLES, "java")


def _ids_from_source(scanner, filename, source, language):
    """Parse an in-memory snippet and return the set of rule ids it raises."""
    parsed = ts.parse_source(source, filename, language)
    assert parsed is not None and parsed.ok
    findings = scanner._scan_tree(parsed)
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# Grammar availability sanity check
# ---------------------------------------------------------------------------
def test_treesitter_is_available():
    assert ts.is_available()
    assert ts.language_for_extension(".js") == "javascript"
    assert ts.language_for_extension(".ts") == "typescript"
    assert ts.language_for_extension(".java") == "java"


# ---------------------------------------------------------------------------
# JavaScript: vulnerable detections
# ---------------------------------------------------------------------------
def test_javascript_detects_core_vulnerabilities():
    scanner = JavaScriptScanner()
    findings = scanner.scan_files(
        [os.path.join(JS_DIR, "vulnerable.js")], base_dir=SAMPLES
    )
    ids = {f.rule_id for f in findings}
    assert "SG-JS001" in ids   # eval
    assert "SG-JS002" in ids   # child_process.exec
    assert "SG-JS003" in ids   # innerHTML XSS
    assert "SG-JS004" in ids   # SQL concatenation
    assert "SG-JS005" in ids   # hardcoded secret
    # Every finding must carry the language and engine tag.
    assert all(f.language == "javascript" for f in findings)
    assert all(f.engines == ["javascript"] for f in findings)


def test_javascript_safe_code_has_no_findings():
    scanner = JavaScriptScanner()
    findings = scanner.scan_files(
        [os.path.join(JS_DIR, "safe", "safe.js")], base_dir=SAMPLES
    )
    ids = {f.rule_id for f in findings}
    for rid in ("SG-JS001", "SG-JS002", "SG-JS003", "SG-JS004", "SG-JS005"):
        assert rid not in ids, f"false positive: {rid} on safe.js"


def test_javascript_regex_exec_not_flagged_as_command():
    scanner = JavaScriptScanner()
    ids = _ids_from_source(
        scanner, "snippet.js",
        "const re = /x/; const m = re.exec(userInput);",
        "javascript",
    )
    assert "SG-JS002" not in ids


def test_javascript_constant_eval_lower_risk():
    scanner = JavaScriptScanner()
    # A dynamic eval must be flagged; a pure constant literal must not.
    dyn = _ids_from_source(scanner, "d.js", "eval('x' + userInput);", "javascript")
    const = _ids_from_source(scanner, "c.js", "eval('1 + 1');", "javascript")
    assert "SG-JS001" in dyn
    assert "SG-JS001" not in const


# ---------------------------------------------------------------------------
# Java: vulnerable detections
# ---------------------------------------------------------------------------
def test_java_detects_core_vulnerabilities():
    scanner = JavaScanner()
    findings = scanner.scan_files(
        [os.path.join(JAVA_DIR, "Vulnerable.java")], base_dir=SAMPLES
    )
    ids = {f.rule_id for f in findings}
    assert "SG-JAVA001" in ids  # Runtime.exec
    assert "SG-JAVA002" in ids  # SQL concatenation
    assert "SG-JAVA003" in ids  # insecure deserialization
    assert "SG-JAVA004" in ids  # weak hash MD5
    assert "SG-JAVA005" in ids  # hardcoded secret
    assert all(f.language == "java" for f in findings)
    assert all(f.engines == ["java"] for f in findings)


def test_java_safe_code_has_no_findings():
    scanner = JavaScanner()
    findings = scanner.scan_files(
        [os.path.join(JAVA_DIR, "safe", "Safe.java")], base_dir=SAMPLES
    )
    ids = {f.rule_id for f in findings}
    for rid in ("SG-JAVA001", "SG-JAVA002", "SG-JAVA003", "SG-JAVA004", "SG-JAVA005"):
        assert rid not in ids, f"false positive: {rid} on Safe.java"


def test_java_sha256_not_flagged():
    scanner = JavaScanner()
    ids = _ids_from_source(
        scanner, "H.java",
        'class H { void f() throws Exception { '
        'java.security.MessageDigest.getInstance("SHA-256"); } }',
        "java",
    )
    assert "SG-JAVA004" not in ids


# ---------------------------------------------------------------------------
# Mixed-language project through the full engine + Security Gate
# ---------------------------------------------------------------------------
def test_mixed_project_scan_covers_all_languages(tmp_path):
    """A project containing Python, JavaScript and Java yields findings for
    each language via the single SastEngine entry point, and those findings
    flow into the Security Gate."""
    # Python file (native AST engine).
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def h(cmd):\n"
        "    os.system('echo ' + cmd)\n",
        encoding="utf-8",
    )
    # JavaScript file (Tree-sitter JS scanner).
    (tmp_path / "app.js").write_text(
        "const cp = require('child_process');\n"
        "function f(req){ cp.exec('ls ' + req.query.dir); }\n",
        encoding="utf-8",
    )
    # Java file (Tree-sitter Java scanner).
    (tmp_path / "App.java").write_text(
        "class App {\n"
        "  Process f(String s) throws Exception {\n"
        "    return Runtime.getRuntime().exec(\"sh -c \" + s);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    engine = SastEngine()
    # Keep the test deterministic without bandit/semgrep installed.
    result = engine.scan_path(str(tmp_path), use_bandit=False, use_semgrep=False)

    languages = {f.language for f in result.findings}
    assert "python" in languages
    assert "javascript" in languages
    assert "java" in languages

    assert "javascript" in result.engines_run
    assert "java" in result.engines_run
    assert result.total_files == 3

    # Security Gate receives the multi-language findings via severity counts.
    counts = severity_counts(result.findings)
    evaluation = evaluate_gate(counts)
    assert evaluation.critical + evaluation.high >= 2
    # The JS and Java command-execution findings are CRITICAL -> gate FAILs.
    assert evaluation.status.value == "FAIL"
