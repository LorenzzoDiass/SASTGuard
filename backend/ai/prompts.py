"""Prompt templates for the local LLM security analysis.

The AI is a *second opinion* layer: it never performs primary detection. It
only receives the already-detected finding context and returns structured JSON.
"""
from __future__ import annotations

SYSTEM_PROMPT = (
    "You are a senior application security engineer assisting a SAST platform. "
    "A deterministic static analyzer has ALREADY detected a potential "
    "vulnerability. Your job is to review that finding and respond ONLY with a "
    "single valid JSON object (no markdown, no prose outside JSON). "
    "Assess whether it is a likely true positive, estimate severity and "
    "confidence, explain impact, and propose a concrete fix with corrected code."
)

# The JSON contract the model must follow.
RESPONSE_SCHEMA = {
    "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
    "confidence": "float between 0 and 1",
    "possible_false_positive": "boolean",
    "explanation": "string: what the vulnerability is",
    "impact": "string: what an attacker could achieve",
    "remediation": "string: how to fix it",
    "fixed_code": "string: a corrected version of the vulnerable snippet",
}


def build_user_prompt(finding: dict) -> str:
    """Build the user prompt from a finding dict (only necessary context)."""
    taint = finding.get("taint_path")
    taint_text = ""
    if taint:
        steps = "\n".join(
            f"  - {s.get('kind')}: {s.get('description')} (line {s.get('line')})"
            for s in taint
        )
        taint_text = f"\nData-flow (taint) path:\n{steps}\n"

    schema_lines = "\n".join(f'  "{k}": {v}' for k, v in RESPONSE_SCHEMA.items())

    return (
        f"Vulnerability detected by static analysis:\n"
        f"- Rule: {finding.get('rule_id')} - {finding.get('title')}\n"
        f"- Detected severity: {finding.get('severity')}\n"
        f"- CWE: {finding.get('cwe')}\n"
        f"- OWASP: {finding.get('owasp')}\n"
        f"- File: {finding.get('file_path')} (line {finding.get('line')})\n"
        f"- Description: {finding.get('description')}\n"
        f"{taint_text}"
        f"\nVulnerable code snippet:\n```python\n{finding.get('code_snippet')}\n```\n"
        f"\nRespond with ONLY a JSON object using exactly these keys:\n"
        f"{{\n{schema_lines}\n}}\n"
    )
