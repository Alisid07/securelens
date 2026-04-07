"""
SecureLens Report Generator

Supports three output formats:
  - JSON   : machine-readable, CI-friendly
  - Markdown: human-readable summary for PRs and wikis
  - SARIF  : Static Analysis Results Interchange Format (GitHub code scanning)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .scanner import ScanResult, Severity


ReportFormat = Literal["json", "markdown", "sarif"]


# ─────────────────────────────────────────────
# Severity emoji helpers
# ─────────────────────────────────────────────

_SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH:     "🟠 HIGH",
    Severity.MEDIUM:   "🟡 MEDIUM",
    Severity.LOW:      "🟢 LOW",
    Severity.INFO:     "⚪ INFO",
}

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}


# ─────────────────────────────────────────────
# Report generators
# ─────────────────────────────────────────────

def generate_json(results: list[ScanResult], indent: int = 2) -> str:
    payload = {
        "tool":       "SecureLens",
        "version":    "0.1.0",
        "generated":  datetime.now(timezone.utc).isoformat(),
        "summary": {
            "files_scanned":       len(results),
            "total_vulnerabilities": sum(len(r.vulnerabilities) for r in results),
            "passed":              sum(1 for r in results if r.passed),
            "failed":              sum(1 for r in results if not r.passed),
            "total_risk_score":    sum(r.risk_score for r in results),
        },
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=indent)


def generate_markdown(results: list[ScanResult]) -> str:
    lines: list[str] = []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    total_vulns = sum(len(r.vulnerabilities) for r in results)
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    lines += [
        "# 🔍 SecureLens Security Report",
        f"_Generated: {ts}_",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Files Scanned | {len(results)} |",
        f"| Total Vulnerabilities | {total_vulns} |",
        f"| ✅ Passed | {passed} |",
        f"| ❌ Failed | {failed} |",
        "",
    ]

    for result in results:
        status = "✅ PASSED" if result.passed else "❌ FAILED"
        lines += [
            "---",
            f"## `{result.file}`  {status}",
            f"- **Language**: {result.language}",
            f"- **Risk Score**: {result.risk_score}",
            f"- **Scan Time**: {result.scan_time_ms} ms",
            "",
        ]

        if result.llm_summary:
            lines += [
                "### 🤖 AI Review",
                f"> {result.llm_summary}",
                "",
            ]

        if not result.vulnerabilities:
            lines += ["_No vulnerabilities detected._", ""]
            continue

        lines += ["### Findings", ""]

        for vuln in result.vulnerabilities:
            badge = _SEVERITY_BADGE[vuln.severity]
            lines += [
                f"#### {badge} — {vuln.title} (`{vuln.rule_id}`)",
                f"- **Line**: {vuln.line}",
                f"- **CWE**: {vuln.cwe or 'N/A'}",
                f"- **Description**: {vuln.description}",
                f"- **Suggestion**: {vuln.suggestion}",
                "```",
                vuln.snippet,
                "```",
                "",
            ]

    return "\n".join(lines)


def generate_sarif(results: list[ScanResult]) -> str:
    """
    Produces SARIF 2.1.0 — compatible with GitHub Advanced Security
    code scanning uploads.
    """
    rules_seen: dict[str, dict] = {}
    run_results: list[dict] = []

    for result in results:
        for vuln in result.vulnerabilities:
            if vuln.rule_id not in rules_seen:
                rules_seen[vuln.rule_id] = {
                    "id": vuln.rule_id,
                    "name": vuln.title.replace(" ", ""),
                    "shortDescription": {"text": vuln.title},
                    "fullDescription": {"text": vuln.description},
                    "help": {"text": vuln.suggestion, "markdown": vuln.suggestion},
                    "properties": {
                        "tags": [vuln.cwe] if vuln.cwe else [],
                        "precision": "high",
                        "problem.severity": _SARIF_LEVEL[vuln.severity],
                    },
                }

            run_results.append({
                "ruleId": vuln.rule_id,
                "level": _SARIF_LEVEL[vuln.severity],
                "message": {"text": f"{vuln.description} — {vuln.suggestion}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": vuln.file},
                        "region": {
                            "startLine": vuln.line,
                            "snippet": {"text": vuln.snippet},
                        },
                    }
                }],
            })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecureLens",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/Alisid07/securelens",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": run_results,
        }],
    }
    return json.dumps(sarif, indent=2)


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def write_report(
    results: list[ScanResult],
    output_path: Path,
    fmt: ReportFormat = "json",
) -> None:
    generators = {
        "json":     generate_json,
        "markdown": generate_markdown,
        "sarif":    generate_sarif,
    }
    content = generators[fmt](results)
    output_path.write_text(content, encoding="utf-8")
    print(f"[SecureLens] Report written to {output_path}")
