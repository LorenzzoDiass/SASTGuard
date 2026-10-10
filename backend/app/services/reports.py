"""Report generation: JSON, HTML and SARIF 2.1.0.

Works directly off engine Finding dataclasses so it can run from the CLI
without a database.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, List

from sast.engine import severity_counts
from sast.models import Finding


def to_json(findings: List[Finding], meta: Dict = None) -> str:
    meta = meta or {}
    payload = {
        "tool": "SASTGuard",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total": len(findings),
            "by_severity": severity_counts(findings),
            **meta,
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


_SEV_COLORS = {
    "CRITICAL": "#b00020",
    "HIGH": "#e65100",
    "MEDIUM": "#f9a825",
    "LOW": "#2e7d32",
    "INFO": "#1565c0",
}


def to_html(findings: List[Finding], meta: Dict = None) -> str:
    meta = meta or {}
    counts = severity_counts(findings)
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {_SEV_COLORS[s]}">'
        f'<div class="n">{counts.get(s,0)}</div><div class="l">{s}</div></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    rows = []
    for f in findings:
        taint = ""
        if f.taint_path:
            steps = " &rarr; ".join(
                f"<b>{s.kind}</b>: {_esc(s.description)}" for s in f.taint_path
            )
            taint = f'<div class="taint">{steps}</div>'
        rows.append(
            f"<tr>"
            f'<td><span class="sev" style="background:{_SEV_COLORS.get(f.severity.value,"#555")}">'
            f"{f.severity.value}</span></td>"
            f"<td>{_esc(f.rule_id)}</td>"
            f"<td>{_esc(f.title)}</td>"
            f"<td>{_esc(f.file_path)}:{f.line}</td>"
            f"<td>{_esc(f.cwe or '')}</td>"
            f"<td>{_esc('+'.join(f.engines))}</td>"
            f"<td><code>{_esc(f.code_snippet)}</code>{taint}</td>"
            f"</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SASTGuard Report</title>
<style>
 body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0d1117;color:#e6edf3}}
 header{{background:#161b22;padding:20px 32px;border-bottom:1px solid #30363d}}
 h1{{margin:0;font-size:22px}} .sub{{color:#8b949e;font-size:13px}}
 .cards{{display:flex;gap:16px;padding:24px 32px;flex-wrap:wrap}}
 .card{{background:#161b22;border-radius:8px;padding:16px 24px;min-width:110px;text-align:center}}
 .card .n{{font-size:28px;font-weight:700}} .card .l{{color:#8b949e;font-size:12px}}
 table{{width:calc(100% - 64px);margin:0 32px 32px;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}}
 th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid #30363d;font-size:13px;vertical-align:top}}
 th{{background:#21262d;color:#8b949e;text-transform:uppercase;font-size:11px}}
 .sev{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}}
 code{{background:#0d1117;padding:2px 6px;border-radius:4px;display:block;white-space:pre-wrap;color:#79c0ff}}
 .taint{{margin-top:6px;color:#d29922;font-size:12px}}
</style></head><body>
<header><h1>🛡️ SASTGuard Security Report</h1>
<div class="sub">Project: {_esc(str(meta.get('project','-')))} &middot;
 Generated: {datetime.utcnow().isoformat()}Z &middot;
 Total findings: {len(findings)}</div></header>
<div class="cards">{cards}</div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Vulnerability</th><th>File:Line</th>
<th>CWE</th><th>Engine</th><th>Code / Taint path</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</body></html>"""


def to_sarif(findings: List[Finding], meta: Dict = None) -> str:
    """Produce a SARIF 2.1.0 document (GitHub code-scanning compatible)."""
    meta = meta or {}
    rules_index: Dict[str, int] = {}
    rules: List[dict] = []
    results: List[dict] = []

    for f in findings:
        if f.rule_id not in rules_index:
            rules_index[f.rule_id] = len(rules)
            rules.append({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "helpUri": "https://cwe.mitre.org/",
                "properties": {
                    "tags": [t for t in [f.cwe, f.owasp] if t],
                    "security-severity": _sarif_score(f.severity.value),
                },
            })
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rules_index[f.rule_id],
            "level": _sarif_level(f.severity.value),
            "message": {"text": f"{f.title}: {f.description}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": max(1, f.line), "startColumn": max(1, f.column or 1)},
                }
            }],
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence,
                "engines": f.engines,
                "cwe": f.cwe,
            },
        })

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SASTGuard",
                "informationUri": "https://example.com/sastguard",
                "version": "1.0.0",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def _sarif_level(severity: str) -> str:
    return {
        "CRITICAL": "error", "HIGH": "error",
        "MEDIUM": "warning", "LOW": "note", "INFO": "note",
    }.get(severity, "warning")


def _sarif_score(severity: str) -> str:
    return {
        "CRITICAL": "9.5", "HIGH": "8.0",
        "MEDIUM": "5.0", "LOW": "3.0", "INFO": "1.0",
    }.get(severity, "5.0")


def _esc(text) -> str:
    s = str(text)
    return (s.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
