"""Definitions of taint sources, sinks and sanitizers.

Each entry maps a dotted call name (or attribute pattern) to metadata used when
building findings. Extending taint coverage is just adding entries here.
"""
from __future__ import annotations

from app.core.enums import Severity

# --- SOURCES ---------------------------------------------------------------
# Dotted call names whose return value is attacker-controlled.
SOURCE_CALLS = {
    "input",
    "sys.argv",                 # subscript handled separately
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.args",
    "request.form",
    "request.json",
    "request.get_json",
    "request.cookies.get",
    "request.headers.get",
    "os.environ.get",
    "flask.request.args.get",
}

# Attribute chains (no call) that are tainted when read, e.g. request.args["x"].
SOURCE_ATTRS = {
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.cookies",
    "request.headers",
    "sys.argv",
    "os.environ",
}


# --- SINKS -----------------------------------------------------------------
# Maps a sink category to its dotted call names and finding metadata.
SINKS = {
    "sql": {
        "calls": {"execute", "executemany", "executescript"},
        "attr_only": True,          # match <obj>.execute(...)
        "rule_id": "TAINT-SQLI",
        "title": "SQL Injection (tainted data reaches query execution)",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "severity": Severity.CRITICAL,
        "recommendation": (
            "Use parameterized queries (cursor.execute(sql, params)); never "
            "concatenate or format untrusted input into SQL."
        ),
    },
    "command": {
        "calls": {"os.system", "subprocess.run", "subprocess.call",
                  "subprocess.Popen", "subprocess.check_output",
                  "subprocess.check_call", "os.popen"},
        "attr_only": False,
        "rule_id": "TAINT-CMDI",
        "title": "Command Injection (tainted data reaches a shell/command sink)",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "severity": Severity.CRITICAL,
        "recommendation": (
            "Never pass untrusted input to the shell. Use argument lists with "
            "shell=False and validate/allow-list inputs."
        ),
    },
    "code": {
        "calls": {"eval", "exec"},
        "attr_only": False,
        "rule_id": "TAINT-CODE",
        "title": "Code Injection (tainted data reaches eval/exec)",
        "cwe": "CWE-95",
        "owasp": "A03:2021 - Injection",
        "severity": Severity.CRITICAL,
        "recommendation": "Never evaluate untrusted input. Redesign without eval/exec.",
    },
    "path": {
        "calls": {"open"},
        "attr_only": False,
        "rule_id": "TAINT-PATH",
        "title": "Path Traversal (tainted data reaches a file path)",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "severity": Severity.HIGH,
        "recommendation": (
            "Validate and normalize paths; confine access to an allow-listed base "
            "directory (os.path.realpath + startswith check)."
        ),
    },
}


# --- SANITIZERS ------------------------------------------------------------
# If a tainted value passes through one of these, taint is cleared.
SANITIZER_CALLS = {
    "int",
    "float",
    "bool",
    "shlex.quote",
    "html.escape",
    "urllib.parse.quote",
    "re.escape",
    "os.path.basename",
    "secure_filename",
    "werkzeug.utils.secure_filename",
}
