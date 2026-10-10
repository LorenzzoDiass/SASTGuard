"""Tests for AST detection rules - positive and negative cases.

These validate real detection, not just that a function was called.
"""
from tests.conftest import rule_ids


# --- eval / exec -----------------------------------------------------------
def test_eval_detected(run_rules):
    findings = run_rules("eval(user_input)\n")
    assert "SG001" in rule_ids(findings)
    f = next(f for f in findings if f.rule_id == "SG001")
    assert f.severity.value == "CRITICAL"
    assert f.cwe == "CWE-95"


def test_eval_not_detected_in_safe_code(run_rules):
    findings = run_rules("result = 1 + 2\nprint(result)\n")
    assert "SG001" not in rule_ids(findings)


def test_exec_detected(run_rules):
    findings = run_rules("exec(code)\n")
    assert "SG002" in rule_ids(findings)


# --- os.system / subprocess ------------------------------------------------
def test_os_system_detected(run_rules):
    findings = run_rules("import os\nos.system('ls ' + path)\n")
    assert "SG004" in rule_ids(findings)


def test_subprocess_shell_true_detected(run_rules):
    findings = run_rules("import subprocess\nsubprocess.run(cmd, shell=True)\n")
    assert "SG003" in rule_ids(findings)


def test_subprocess_shell_false_not_detected(run_rules):
    findings = run_rules("import subprocess\nsubprocess.run(['ls', path])\n")
    assert "SG003" not in rule_ids(findings)


# --- secrets ---------------------------------------------------------------
def test_hardcoded_password_detected(run_rules):
    findings = run_rules('password = "SuperSecret123"\n')
    assert "SG001-pw" in rule_ids(findings)


def test_hardcoded_password_env_not_detected(run_rules):
    findings = run_rules('import os\npassword = os.environ.get("PW")\n')
    assert "SG001-pw" not in rule_ids(findings)


def test_placeholder_password_not_detected(run_rules):
    findings = run_rules('password = "changeme"\n')
    assert "SG001-pw" not in rule_ids(findings)


def test_api_key_detected(run_rules):
    findings = run_rules('key = "AKIAIOSFODNN7EXAMPLE"\n')
    assert "SECRET-KEY" in rule_ids(findings)


# --- crypto ----------------------------------------------------------------
def test_md5_detected(run_rules):
    findings = run_rules("import hashlib\nhashlib.md5(data)\n")
    assert "SG011" in rule_ids(findings)


def test_sha1_detected(run_rules):
    findings = run_rules("import hashlib\nhashlib.sha1(data)\n")
    assert "SG012" in rule_ids(findings)


def test_sha256_not_detected(run_rules):
    findings = run_rules("import hashlib\nhashlib.sha256(data)\n")
    ids = rule_ids(findings)
    assert "SG011" not in ids and "SG012" not in ids


def test_insecure_random_for_token_is_high(run_rules):
    findings = run_rules("import random\ntoken = random.randint(0, 9)\n")
    sg013 = [f for f in findings if f.rule_id == "SG013"]
    assert sg013
    assert sg013[0].severity.value == "HIGH"


# --- deserialization -------------------------------------------------------
def test_pickle_detected(run_rules):
    findings = run_rules("import pickle\npickle.loads(blob)\n")
    assert "SG009" in rule_ids(findings)


def test_yaml_load_unsafe_detected(run_rules):
    findings = run_rules("import yaml\nyaml.load(stream)\n")
    assert "SG010" in rule_ids(findings)


def test_yaml_safe_load_not_detected(run_rules):
    findings = run_rules("import yaml\nyaml.safe_load(stream)\n")
    assert "SG010" not in rule_ids(findings)


def test_yaml_load_with_safeloader_not_detected(run_rules):
    findings = run_rules("import yaml\nyaml.load(stream, Loader=yaml.SafeLoader)\n")
    assert "SG010" not in rule_ids(findings)


# --- misc ------------------------------------------------------------------
def test_requests_verify_false_detected(run_rules):
    findings = run_rules("import requests\nrequests.get(url, verify=False)\n")
    assert "SG014" in rule_ids(findings)


def test_flask_debug_true_detected(run_rules):
    findings = run_rules("app.run(host='0.0.0.0', debug=True)\n")
    assert "SG015" in rule_ids(findings)


# --- SQL (inline) ----------------------------------------------------------
def test_inline_sql_concat_detected(run_rules):
    findings = run_rules('cursor.execute("SELECT * FROM u WHERE id=" + uid)\n')
    assert "SG007" in rule_ids(findings)


def test_parameterized_sql_not_flagged_by_ast_rule(run_rules):
    findings = run_rules('cursor.execute("SELECT * FROM u WHERE id=%s", (uid,))\n')
    assert "SG007" not in rule_ids(findings)
