"""Tests for taint analysis: sources, propagation, sinks, sanitizers."""


def _ids(findings):
    return [f.rule_id for f in findings]


# --- SQL injection via propagation ----------------------------------------
def test_sqli_source_propagation_sink(run_taint):
    src = (
        "def h():\n"
        "    user_id = request.args.get('id')\n"
        "    query = 'SELECT * FROM users WHERE id = ' + user_id\n"
        "    cursor.execute(query)\n"
    )
    findings = run_taint(src)
    sqli = [f for f in findings if f.rule_id == "TAINT-SQLI"]
    assert len(sqli) == 1
    kinds = [s.kind for s in sqli[0].taint_path]
    assert kinds == ["SOURCE", "PROPAGATION", "SINK"]


def test_sqli_taint_path_describes_source(run_taint):
    src = (
        "def h():\n"
        "    uid = request.args.get('id')\n"
        "    q = 'SELECT ' + uid\n"
        "    cursor.execute(q)\n"
    )
    findings = run_taint(src)
    sqli = next(f for f in findings if f.rule_id == "TAINT-SQLI")
    source_step = sqli.taint_path[0]
    assert "request.args.get" in source_step.description


# --- parameterized SQL is safe ---------------------------------------------
def test_parameterized_sql_is_safe(run_taint):
    src = (
        "def h():\n"
        "    user_id = request.args.get('id')\n"
        "    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
    )
    findings = run_taint(src)
    assert "TAINT-SQLI" not in _ids(findings)


# --- command injection -----------------------------------------------------
def test_command_injection_detected(run_taint):
    src = (
        "def r():\n"
        "    name = input()\n"
        "    os.system('echo ' + name)\n"
    )
    findings = run_taint(src)
    assert "TAINT-CMDI" in _ids(findings)


def test_safe_argv_subprocess_not_flagged(run_taint):
    src = (
        "def r():\n"
        "    name = request.args.get('n')\n"
        "    subprocess.run(['echo', name], shell=False)\n"
    )
    findings = run_taint(src)
    assert "TAINT-CMDI" not in _ids(findings)


# --- sanitizers ------------------------------------------------------------
def test_int_sanitizer_clears_taint(run_taint):
    src = (
        "def r():\n"
        "    uid = int(request.args.get('id'))\n"
        "    cursor.execute('SELECT * FROM u WHERE id = ' + str(uid))\n"
    )
    findings = run_taint(src)
    assert "TAINT-SQLI" not in _ids(findings)


def test_basename_sanitizer_for_path(run_taint):
    src = (
        "def read(base):\n"
        "    fn = request.args.get('file')\n"
        "    full = os.path.join(base, os.path.basename(fn))\n"
        "    open(full)\n"
    )
    findings = run_taint(src)
    assert "TAINT-PATH" not in _ids(findings)


# --- path traversal --------------------------------------------------------
def test_path_traversal_detected(run_taint):
    src = (
        "def read():\n"
        "    fn = request.args.get('file')\n"
        "    open(fn)\n"
    )
    findings = run_taint(src)
    assert "TAINT-PATH" in _ids(findings)


# --- no false positive on constant data ------------------------------------
def test_no_taint_on_constant_query(run_taint):
    src = (
        "def h():\n"
        "    cursor.execute('SELECT 1')\n"
    )
    findings = run_taint(src)
    assert findings == []
