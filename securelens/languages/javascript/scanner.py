"""Regex-based security scanner for JavaScript and TypeScript files."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from securelens.config import get_settings
from securelens.exceptions import FileTooLargeError
from securelens.scanner import ScanResult, Severity, Vulnerability

_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


@dataclass
class JSRule:
    rule_id: str
    title: str
    pattern: re.Pattern
    severity: Severity
    description: str
    suggestion: str
    cwe: str = ""


_JS_RULES: list[JSRule] = [
    JSRule(
        rule_id="JS001",
        title="eval() Usage",
        pattern=re.compile(r"\beval\s*\("),
        severity=Severity.HIGH,
        description="eval() executes arbitrary JavaScript; dangerous with user-controlled input.",
        suggestion="Use JSON.parse() for data, or restructure to avoid dynamic code execution.",
        cwe="CWE-95",
    ),
    JSRule(
        rule_id="JS002",
        title="innerHTML Assignment",
        pattern=re.compile(r"\.innerHTML\s*="),
        severity=Severity.HIGH,
        description=(
            "Assigning to innerHTML with user-supplied data can introduce XSS vulnerabilities."
        ),
        suggestion=(
            "Use textContent for plain text, or sanitize HTML with DOMPurify before assignment."
        ),
        cwe="CWE-79",
    ),
    JSRule(
        rule_id="JS003",
        title="document.write() Usage",
        pattern=re.compile(r"document\.write\s*\("),
        severity=Severity.MEDIUM,
        description=(
            "document.write() can overwrite the entire page and enable XSS with user data."
        ),
        suggestion="Use DOM manipulation methods (createElement, appendChild) instead.",
        cwe="CWE-79",
    ),
    JSRule(
        rule_id="JS004",
        title="Hardcoded Secret",
        pattern=re.compile(
            r"(?i)(password|secret|api_key|apikey|token|passwd)\s*[=:]\s*[\"'][^\"']{4,}[\"']"
        ),
        severity=Severity.CRITICAL,
        description="A credential or secret appears hardcoded in JavaScript source.",
        suggestion=(
            "Use environment variables injected at build time; "
            "never ship secrets in client-side code."
        ),
        cwe="CWE-798",
    ),
    JSRule(
        rule_id="JS005",
        title="postMessage Listener Without Origin Check",
        pattern=re.compile(r"addEventListener\s*\(\s*[\"']message[\"']"),
        severity=Severity.MEDIUM,
        description=(
            "A postMessage listener may not validate event.origin, "
            "enabling cross-origin data injection."
        ),
        suggestion=(
            "Always validate event.origin against an explicit allowlist "
            "before processing postMessage data."
        ),
        cwe="CWE-346",
    ),
    JSRule(
        rule_id="JS006",
        title="setTimeout/setInterval with String Argument",
        pattern=re.compile(r"set(?:Timeout|Interval)\s*\(\s*[\"']"),
        severity=Severity.HIGH,
        description=(
            "Passing a string to setTimeout/setInterval evaluates it as code, "
            "equivalent to eval()."
        ),
        suggestion="Pass a function reference instead of a string.",
        cwe="CWE-95",
    ),
    JSRule(
        rule_id="JS007",
        title="Prototype Pollution Risk",
        pattern=re.compile(r"__proto__|prototype\s*\["),
        severity=Severity.HIGH,
        description=(
            "Direct manipulation of __proto__ or prototype can enable "
            "prototype pollution attacks."
        ),
        suggestion=(
            "Validate keys against an allowlist; "
            "use Object.create(null) for plain dictionary objects."
        ),
        cwe="CWE-1321",
    ),
    JSRule(
        rule_id="JS008",
        title="SQL Injection Risk (Node.js)",
        pattern=re.compile(r"\.query\s*\(\s*`[^`]*\$\{|\.query\s*\(\s*[\"'][^\"']*\s*\+"),
        severity=Severity.HIGH,
        description="String interpolation in a database query call can allow SQL injection.",
        suggestion=(
            "Use parameterised queries or an ORM that handles escaping automatically."
        ),
        cwe="CWE-89",
    ),
    JSRule(
        rule_id="JS009",
        title="Insecure Randomness (Math.random)",
        pattern=re.compile(r"\bMath\.random\s*\("),
        severity=Severity.MEDIUM,
        description="Math.random() is not cryptographically secure.",
        suggestion=(
            "Use crypto.getRandomValues() in the browser or "
            "crypto.randomBytes() in Node.js."
        ),
        cwe="CWE-338",
    ),
    JSRule(
        rule_id="JS010",
        title="CORS Wildcard Origin",
        pattern=re.compile(
            r"Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']?\s*\*"
        ),
        severity=Severity.MEDIUM,
        description=(
            "A wildcard CORS origin allows any external site to make "
            "credentialed cross-origin requests."
        ),
        suggestion=(
            "Restrict Access-Control-Allow-Origin to an explicit allowlisted domain."
        ),
        cwe="CWE-942",
    ),
    JSRule(
        rule_id="JS011",
        title="SSL Verification Disabled (Node.js)",
        pattern=re.compile(r"rejectUnauthorized\s*:\s*false"),
        severity=Severity.HIGH,
        description=(
            "Setting rejectUnauthorized: false disables TLS certificate "
            "verification, exposing connections to MITM attacks."
        ),
        suggestion=(
            "Remove rejectUnauthorized: false. "
            "Use a proper CA bundle if connecting to a custom PKI."
        ),
        cwe="CWE-295",
    ),
    JSRule(
        rule_id="JS012",
        title="outerHTML Assignment",
        pattern=re.compile(r"\.outerHTML\s*="),
        severity=Severity.HIGH,
        description=(
            "Assigning to outerHTML replaces the element with arbitrary HTML, "
            "enabling XSS if the value contains user data."
        ),
        suggestion="Use DOM methods and sanitize any HTML with DOMPurify.",
        cwe="CWE-79",
    ),
]

# Single-line comment prefixes to skip (reduces false positives)
_COMMENT_PREFIXES = ("//", "*", "/*")


class JavaScriptScanner:
    """Regex-based security scanner for JavaScript and TypeScript source.

    Applies each JSRule per line, skipping single-line comment lines to
    reduce false positives from commented-out code examples.
    """

    _TYPESCRIPT_SUFFIXES = {".ts", ".tsx"}

    def __init__(self, extra_rules: list[JSRule] | None = None) -> None:
        self._rules = _JS_RULES + (extra_rules or [])
        self._settings = get_settings()

    # ─── Public API ──────────────────────────────────────────

    def scan_file(self, path: Path) -> ScanResult:
        size = path.stat().st_size
        if size > self._settings.max_file_size:
            raise FileTooLargeError(str(path), size, self._settings.max_file_size)
        code = path.read_text(encoding="utf-8", errors="replace")
        lang = "typescript" if path.suffix in self._TYPESCRIPT_SUFFIXES else "javascript"
        return self.scan_code(code, filename=str(path), language=lang)

    def scan_code(
        self,
        code: str,
        filename: str = "<stdin>",
        language: str = "javascript",
    ) -> ScanResult:
        t0 = time.perf_counter()
        findings: list[Vulnerability] = []

        for lineno, line in enumerate(code.splitlines(), start=1):
            stripped = line.strip()
            if any(stripped.startswith(p) for p in _COMMENT_PREFIXES):
                continue
            for rule in self._rules:
                if rule.pattern.search(line):
                    findings.append(
                        Vulnerability(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            description=rule.description,
                            severity=rule.severity,
                            file=filename,
                            line=lineno,
                            snippet=stripped[:120],
                            suggestion=rule.suggestion,
                            cwe=rule.cwe,
                        )
                    )

        findings.sort(key=lambda v: (-_SEVERITY_RANK[v.severity], v.line))
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return ScanResult(
            file=filename,
            language=language,
            vulnerabilities=findings,
            scan_time_ms=elapsed_ms,
        )
