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


ReportFormat = Literal["json", "markdown", "sarif", "html"]


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
# HTML report
# ─────────────────────────────────────────────

_HTML_SEVERITY_CLASS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH:     "high",
    Severity.MEDIUM:   "medium",
    Severity.LOW:      "low",
    Severity.INFO:     "info",
}

_HTML_CSS = """\
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f5f6fa; color: #2d3436; line-height: 1.6; }
  header { background: #2d3436; color: #fff; padding: 24px 32px; }
  header h1 { font-size: 1.6rem; font-weight: 700; letter-spacing: -.5px; }
  header p  { opacity: .7; font-size: .9rem; margin-top: 4px; }
  .container { max-width: 1100px; margin: 0 auto; padding: 32px 16px; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                  gap: 16px; margin-bottom: 32px; }
  .card { background: #fff; border-radius: 8px; padding: 20px; text-align: center;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .card .value { font-size: 2rem; font-weight: 700; }
  .card .label { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em;
                 color: #636e72; margin-top: 4px; }
  .file-block { background: #fff; border-radius: 8px; margin-bottom: 24px;
                box-shadow: 0 1px 3px rgba(0,0,0,.08); overflow: hidden; }
  .file-header { display: flex; justify-content: space-between; align-items: center;
                 padding: 14px 20px; background: #f8f9fa; border-bottom: 1px solid #e9ecef; }
  .file-header code { font-size: .9rem; font-weight: 600; }
  .file-meta { font-size: .8rem; color: #636e72; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px;
           font-size: .75rem; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; }
  .badge.critical { background: #ffeaa7; color: #6c5ce7; border: 1px solid #a29bfe; }
  .badge.high     { background: #fab1a0; color: #c0392b; border: 1px solid #e17055; }
  .badge.medium   { background: #ffeaa7; color: #e17055; border: 1px solid #fdcb6e; }
  .badge.low      { background: #dfe6e9; color: #2d3436; border: 1px solid #b2bec3; }
  .badge.info     { background: #dfe6e9; color: #636e72; border: 1px solid #b2bec3; }
  .badge.passed   { background: #00b894; color: #fff; border: none; }
  .badge.failed   { background: #d63031; color: #fff; border: none; }
  .finding { border-left: 4px solid #ddd; margin: 16px 20px; padding: 12px 16px;
             border-radius: 0 6px 6px 0; background: #f8f9fa; }
  .finding.critical { border-color: #6c5ce7; }
  .finding.high     { border-color: #d63031; }
  .finding.medium   { border-color: #e17055; }
  .finding.low      { border-color: #b2bec3; }
  .finding.info     { border-color: #74b9ff; }
  .finding-title { font-weight: 600; margin-bottom: 6px; display: flex;
                   align-items: center; gap: 8px; }
  .finding-meta  { font-size: .8rem; color: #636e72; margin-bottom: 8px; }
  .finding p     { font-size: .9rem; margin-bottom: 4px; }
  pre { background: #2d3436; color: #dfe6e9; padding: 10px 14px; border-radius: 6px;
        font-size: .82rem; overflow-x: auto; margin-top: 8px; white-space: pre-wrap;
        word-break: break-all; }
  .ai-review { margin: 12px 20px 16px; padding: 12px 16px; background: #f0f3ff;
               border-left: 4px solid #6c5ce7; border-radius: 0 6px 6px 0;
               font-size: .9rem; font-style: italic; }
  .no-findings { padding: 20px; color: #00b894; font-weight: 600; }
  footer { text-align: center; padding: 24px; font-size: .8rem; color: #b2bec3; }
"""


def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


def generate_html(results: list[ScanResult]) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    total_score = sum(r.risk_score for r in results)

    # ── Summary cards ──────────────────────────────────────
    cards = [
        (str(len(results)), "Files Scanned"),
        (str(total_vulns), "Vulnerabilities"),
        (str(passed), "Passed"),
        (str(failed), "Failed"),
        (str(total_score), "Total Risk Score"),
    ]
    cards_html = "\n".join(
        f'      <div class="card"><div class="value">{v}</div>'
        f'<div class="label">{l}</div></div>'
        for v, l in cards
    )

    # ── Per-file blocks ─────────────────────────────────────
    file_blocks: list[str] = []
    for result in results:
        status_cls = "passed" if result.passed else "failed"
        status_txt = "PASSED" if result.passed else "FAILED"
        header = (
            f'    <div class="file-block">\n'
            f'      <div class="file-header">\n'
            f'        <code>{_html_escape(result.file)}</code>\n'
            f'        <span class="file-meta">'
            f'{result.language} &nbsp;|&nbsp; '
            f'risk {result.risk_score} &nbsp;|&nbsp; '
            f'{result.scan_time_ms} ms</span>\n'
            f'        <span class="badge {status_cls}">{status_txt}</span>\n'
            f'      </div>'
        )

        ai_block = ""
        if result.llm_summary:
            ai_block = (
                f'\n      <div class="ai-review">'
                f'&#129302; AI Review: {_html_escape(result.llm_summary)}'
                f"</div>"
            )

        if not result.vulnerabilities:
            body = '\n      <p class="no-findings">&#10003; No vulnerabilities detected.</p>'
        else:
            finding_parts: list[str] = []
            for vuln in result.vulnerabilities:
                cls = _HTML_SEVERITY_CLASS[vuln.severity]
                finding_parts.append(
                    f'      <div class="finding {cls}">\n'
                    f'        <div class="finding-title">'
                    f'<span class="badge {cls}">{vuln.severity.value}</span>'
                    f" {_html_escape(vuln.title)}"
                    f" <small>({vuln.rule_id})</small></div>\n"
                    f'        <div class="finding-meta">'
                    f"Line {vuln.line}"
                    + (f" &nbsp;|&nbsp; {vuln.cwe}" if vuln.cwe else "")
                    + "</div>\n"
                    f"        <p>{_html_escape(vuln.description)}</p>\n"
                    f"        <p><strong>Fix:</strong> {_html_escape(vuln.suggestion)}</p>\n"
                    + (
                        f"        <pre>{_html_escape(vuln.snippet)}</pre>\n"
                        if vuln.snippet
                        else ""
                    )
                    + "      </div>"
                )
            body = "\n" + "\n".join(finding_parts)

        file_blocks.append(f"{header}{ai_block}{body}\n    </div>")

    files_html = "\n".join(file_blocks)

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SecureLens Security Report</title>
  <style>
{_HTML_CSS}
  </style>
</head>
<body>
  <header>
    <h1>&#128269; SecureLens Security Report</h1>
    <p>Generated: {ts}</p>
  </header>
  <div class="container">
    <div class="summary-grid">
{cards_html}
    </div>
{files_html}
  </div>
  <footer>Generated by <strong>SecureLens</strong></footer>
</body>
</html>
"""


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
        "html":     generate_html,
    }
    content = generators[fmt](results)
    output_path.write_text(content, encoding="utf-8")
    print(f"[SecureLens] Report written to {output_path}")
