"""SASTGuard command-line interface for CI/CD.

Usage:
    python -m app.cli scan <path> [--gate] [--json FILE] [--html FILE]
                                  [--sarif FILE] [--no-bandit] [--no-semgrep]
                                  [--fail-critical N] [--fail-high N] [--warn-medium N]

Exit codes:
    0 = PASS (or scan ok without --gate)
    1 = Security Gate FAIL
    2 = tool error
"""
from __future__ import annotations

import argparse
import os
import sys

from app.services.security_gate import evaluate_gate, GatePolicy
from app.services import reports
from app.core.enums import GateStatus
from sast.engine import SastEngine, severity_counts


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sastguard", description="SASTGuard SAST CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a path for vulnerabilities")
    scan.add_argument("path", help="File or directory to scan")
    scan.add_argument("--gate", action="store_true", help="Apply the security gate")
    scan.add_argument("--json", dest="json_out", metavar="FILE", help="Write JSON report")
    scan.add_argument("--html", dest="html_out", metavar="FILE", help="Write HTML report")
    scan.add_argument("--sarif", dest="sarif_out", metavar="FILE", help="Write SARIF report")
    scan.add_argument("--no-bandit", action="store_true", help="Disable Bandit")
    scan.add_argument("--no-semgrep", action="store_true", help="Disable Semgrep")
    scan.add_argument("--fail-critical", type=int, default=None)
    scan.add_argument("--fail-high", type=int, default=None)
    scan.add_argument("--warn-medium", type=int, default=None)
    return parser


def _run_scan(args) -> int:
    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    try:
        semgrep_rules = os.path.join(os.getcwd(), "semgrep_rules")
        semgrep_rules = semgrep_rules if os.path.isdir(semgrep_rules) else None
        engine = SastEngine(semgrep_rules_path=semgrep_rules)
        result = engine.scan_path(
            args.path,
            use_bandit=not args.no_bandit,
            use_semgrep=not args.no_semgrep,
        )
    except Exception as exc:  # noqa: BLE001 - tool error
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 2

    findings = result.findings
    counts = severity_counts(findings)
    meta = {
        "project": os.path.basename(os.path.abspath(args.path)),
        "files_scanned": result.total_files,
        "engines_run": result.engines_run,
    }

    # Reports
    try:
        if args.json_out:
            _write(args.json_out, reports.to_json(findings, meta))
        if args.html_out:
            _write(args.html_out, reports.to_html(findings, meta))
        if args.sarif_out:
            _write(args.sarif_out, reports.to_sarif(findings, meta))
    except OSError as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        return 2

    # Console summary
    print(f"SASTGuard scanned {result.total_files} file(s) "
          f"using engines: {', '.join(result.engines_run)}")
    print(f"Findings: {len(findings)}  "
          f"CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} "
          f"MEDIUM={counts['MEDIUM']} LOW={counts['LOW']} INFO={counts['INFO']}")

    if not args.gate:
        return 0

    policy = GatePolicy()
    if args.fail_critical is not None:
        policy.fail_critical = args.fail_critical
    if args.fail_high is not None:
        policy.fail_high = args.fail_high
    if args.warn_medium is not None:
        policy.warn_medium = args.warn_medium

    evaluation = evaluate_gate(counts, policy)
    print(f"\nSecurity Gate: {evaluation.status.value}")
    for reason in evaluation.reasons:
        print(f"  - {reason}")

    if evaluation.status == GateStatus.FAIL:
        return 1
    return 0


def _write(path: str, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"wrote {path}")


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
