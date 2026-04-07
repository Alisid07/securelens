"""
SecureLens CLI

Usage examples:
  # Scan a single file
  python -m securelens scan app.py

  # Scan a directory, output Markdown
  python -m securelens scan ./src --format markdown --output report.md

  # Scan and output SARIF (for GitHub code scanning)
  python -m securelens scan ./src --format sarif --output results.sarif

  # Fail CI pipeline if risk score exceeds threshold
  python -m securelens scan ./src --fail-on HIGH
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scanner import Scanner, Severity, SEVERITY_SCORE
from .reporter import write_report, generate_markdown, generate_json


SEVERITY_ORDER = [s.value for s in Severity]


def _print_console_summary(results) -> None:
    """Compact, coloured-ish console output for interactive use."""
    RESET  = "\033[0m"
    RED    = "\033[91m"
    ORANGE = "\033[33m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BOLD   = "\033[1m"

    colour_map = {
        "CRITICAL": RED,
        "HIGH":     ORANGE,
        "MEDIUM":   YELLOW,
        "LOW":      GREEN,
        "INFO":     RESET,
    }

    total_vulns = sum(len(r.vulnerabilities) for r in results)
    total_risk  = sum(r.risk_score for r in results)

    print(f"\n{BOLD}SecureLens — Scan Complete{RESET}")
    print(f"{'─' * 50}")
    print(f"  Files scanned      : {len(results)}")
    print(f"  Vulnerabilities    : {total_vulns}")
    print(f"  Total risk score   : {total_risk}")
    print()

    for result in results:
        status = f"{GREEN}PASS{RESET}" if result.passed else f"{RED}FAIL{RESET}"
        print(f"  {BOLD}{result.file}{RESET}  [{status}]  score={result.risk_score}")

        for v in result.vulnerabilities:
            c = colour_map.get(v.severity.value, RESET)
            print(f"    {c}[{v.severity.value}]{RESET}  L{v.line}  {v.title}  ({v.rule_id})")
            print(f"           → {v.suggestion}")

        if result.llm_summary:
            print(f"\n    🤖 AI: {result.llm_summary}\n")

    print(f"{'─' * 50}\n")


def _highest_severity(results) -> Severity | None:
    for sev in Severity:
        for r in results:
            if any(v.severity == sev for v in r.vulnerabilities):
                return sev
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="securelens",
        description="SecureLens — AI-powered code vulnerability reviewer",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan subcommand ──────────────────────────────────────
    scan_cmd = sub.add_parser("scan", help="Scan a file or directory")
    scan_cmd.add_argument("target", type=Path, help="File or directory to scan")
    scan_cmd.add_argument(
        "--format", "-f",
        choices=["console", "json", "markdown", "sarif"],
        default="console",
        help="Output format (default: console)",
    )
    scan_cmd.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Write report to this file (required for non-console formats)",
    )
    scan_cmd.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        default=None,
        help="Exit with code 1 if any finding meets or exceeds this severity",
    )
    scan_cmd.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM review layer (faster for large codebases)",
    )

    # ── rules subcommand ─────────────────────────────────────
    sub.add_parser("rules", help="List all built-in rules")

    args = parser.parse_args(argv)

    # ── rules listing ────────────────────────────────────────
    if args.command == "rules":
        from .scanner import PYTHON_RULES
        print(f"\n{'ID':<8} {'Severity':<10} {'CWE':<10} Title")
        print("─" * 60)
        for r in PYTHON_RULES:
            print(f"{r.rule_id:<8} {r.severity.value:<10} {r.cwe:<10} {r.title}")
        print()
        return 0

    # ── scan ─────────────────────────────────────────────────
    target: Path = args.target
    scanner = Scanner()
    use_llm = not args.no_llm

    if not target.exists():
        print(f"[error] Path not found: {target}", file=sys.stderr)
        return 2

    if target.is_file():
        results = [scanner.scan_file(target, use_llm=use_llm)]
    else:
        results = scanner.scan_directory(target, use_llm=use_llm)

    if not results:
        print("[SecureLens] No scannable files found.")
        return 0

    fmt = args.format

    if fmt == "console":
        _print_console_summary(results)
    elif args.output:
        write_report(results, args.output, fmt=fmt)  # type: ignore[arg-type]
    else:
        # Print to stdout
        if fmt == "json":
            print(generate_json(results))
        elif fmt == "markdown":
            from .reporter import generate_markdown
            print(generate_markdown(results))
        elif fmt == "sarif":
            from .reporter import generate_sarif
            print(generate_sarif(results))

    # Exit code for CI gate
    if args.fail_on:
        threshold = Severity(args.fail_on)
        highest = _highest_severity(results)
        if highest and SEVERITY_SCORE[highest] >= SEVERITY_SCORE[threshold]:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
