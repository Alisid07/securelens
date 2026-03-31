"""
SecureLens Scanner — Core vulnerability detection engine.

Combines static pattern analysis with an LLM review layer.
The LLM client is swappable: plug in OpenAI, Anthropic, or any
compatible provider via the LLMClient protocol.
"""

from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_SCORE = {
    Severity.CRITICAL: 10,
    Severity.HIGH:      7,
    Severity.MEDIUM:    4,
    Severity.LOW:       2,
    Severity.INFO:      0,
}


@dataclass
class Vulnerability:
    rule_id:     str
    title:       str
    description: str
    severity:    Severity
    file:        str
    line:        int
    snippet:     str
    suggestion:  str
    cwe:         str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id":     self.rule_id,
            "title":       self.title,
            "description": self.description,
            "severity":    self.severity.value,
            "file":        self.file,
            "line":        self.line,
            "snippet":     self.snippet,
            "suggestion":  self.suggestion,
            "cwe":         self.cwe,
        }


@dataclass
class ScanResult:
    file:            str
    language:        str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    llm_summary:     str = ""
    scan_time_ms:    float = 0.0

    @property
    def risk_score(self) -> int:
        return sum(SEVERITY_SCORE[v.severity] for v in self.vulnerabilities)

    @property
    def passed(self) -> bool:
        return not any(
            v.severity in (Severity.CRITICAL, Severity.HIGH)
            for v in self.vulnerabilities
        )

    def to_dict(self) -> dict:
        return {
            "file":            self.file,
            "language":        self.language,
            "risk_score":      self.risk_score,
            "passed":          self.passed,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "llm_summary":     self.llm_summary,
            "scan_time_ms":    self.scan_time_ms,
        }


# ─────────────────────────────────────────────
# LLM client protocol (dependency-injection)
# ─────────────────────────────────────────────

@runtime_checkable
class LLMClient(Protocol):
    """Any object implementing `review` can be plugged in as the AI backend."""

    def review(self, code: str, static_findings: list[Vulnerability]) -> str:
        """Return a natural-language security analysis of the code."""
        ...


class MockLLMClient:
    """
    Offline stub — simulates LLM responses without an API key.
    Replace with OpenAIClient or AnthropicClient for real reviews.
    """

    _TEMPLATES = [
        (
            "The code contains {n} static finding(s). The most critical concern is "
            "{top_issue}. Recommend applying the principle of least privilege and "
            "validating all external inputs before processing."
        ),
        (
            "Static analysis flagged {n} issue(s). {top_issue} poses the highest risk "
            "in this file. Consider a security-focused code review and automated "
            "dependency scanning as next steps."
        ),
        (
            "Review complete. {n} potential vulnerability/vulnerabilities detected. "
            "Priority action: address {top_issue}. Ensure secrets are never "
            "hard-coded and all SQL queries use parameterised statements."
        ),
    ]

    def review(self, code: str, static_findings: list[Vulnerability]) -> str:
        import hashlib`n        import random

        seed = int(hashlib.md5(code[:64].encode()).hexdigest(), 16)
        rng = random.Random(seed)

        n = len(static_findings)
        top_issue = (
            static_findings[0].title if static_findings else "no issues detected"
        )
        template = rng.choice(self._TEMPLATES)
        return template.format(n=n, top_issue=top_issue)


# ─────────────────────────────────────────────
# Static rule engine
# ─────────────────────────────────────────────

@dataclass
class Rule:
    rule_id:    str
    title:      str
    pattern:    re.Pattern
    severity:   Severity
    description: str
    suggestion: str
    cwe:        str = ""


PYTHON_RULES: list[Rule] = [
    Rule(
        rule_id="PY001",
        title="Hardcoded Secret",
        pattern=re.compile(
            r'(?i)(password|secret|api_key|token|passwd)\s*=\s*["\'][^"\']{4,}["\']'
        ),
        severity=Severity.CRITICAL,
        description="A credential or secret appears to be hardcoded in source code.",
        suggestion="Use environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).",
        cwe="CWE-798",
    ),
    Rule(
        rule_id="PY002",
        title="SQL Injection Risk",
        pattern=re.compile(
            r'execute\s*\(\s*["\'].*%[s\d]|execute\s*\(\s*f["\']|execute\s*\(\s*.*\.format\('
        ),
        severity=Severity.HIGH,
        description="String interpolation detected inside a SQL execute() call.",
        suggestion="Use parameterised queries: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
        cwe="CWE-89",
    ),
    Rule(
        rule_id="PY003",
        title="Shell Injection via os.system",
        pattern=re.compile(r'os\.system\s*\('),
        severity=Severity.HIGH,
        description="os.system() passes commands directly to the shell; user input can trigger injection.",
        suggestion="Use subprocess.run() with a list of arguments and shell=False.",
        cwe="CWE-78",
    ),
    Rule(
        rule_id="PY004",
        title="Unsafe Deserialization (pickle)",
        pattern=re.compile(r'\bpickle\.loads?\s*\('),
        severity=Severity.HIGH,
        description="pickle.load/loads can execute arbitrary code when loading untrusted data.",
        suggestion="Use JSON or a schema-validated format. If pickle is required, verify HMAC signatures.",
        cwe="CWE-502",
    ),
    Rule(
        rule_id="PY005",
        title="eval() Usage",
        pattern=re.compile(r'\beval\s*\('),
        severity=Severity.HIGH,
        description="eval() executes arbitrary Python code; dangerous with user-controlled input.",
        suggestion="Replace eval() with ast.literal_eval() for safe expression parsing.",
        cwe="CWE-95",
    ),
    Rule(
        rule_id="PY006",
        title="Insecure Hash (MD5/SHA1)",
        pattern=re.compile(r'hashlib\.(md5|sha1)\s*\('),
        severity=Severity.MEDIUM,
        description="MD5 and SHA-1 are cryptographically broken for security-sensitive contexts.",
        suggestion="Use hashlib.sha256() or hashlib.sha3_256() for security-relevant hashing.",
        cwe="CWE-327",
    ),
    Rule(
        rule_id="PY007",
        title="Debug Mode Enabled",
        pattern=re.compile(r'debug\s*=\s*True', re.IGNORECASE),
        severity=Severity.MEDIUM,
        description="Debug mode may expose stack traces and internal state to end users.",
        suggestion="Ensure debug=False in production; control via environment variable.",
        cwe="CWE-215",
    ),
    Rule(
        rule_id="PY008",
        title="Broad Exception Suppression",
        pattern=re.compile(r'except\s*:\s*pass|except\s+Exception\s*:\s*pass'),
        severity=Severity.LOW,
        description="Silently swallowing all exceptions hides bugs and security errors.",
        suggestion="Catch specific exception types and log them appropriately.",
        cwe="CWE-390",
    ),
    Rule(
        rule_id="PY009",
        title="Random Used for Security",
        pattern=re.compile(r'\brandom\.(random|randint|choice|shuffle)\s*\('),
        severity=Severity.MEDIUM,
        description="The random module is not cryptographically secure.",
        suggestion="Use secrets.token_hex() or secrets.choice() for security-sensitive randomness.",
        cwe="CWE-338",
    ),
    Rule(
        rule_id="PY010",
        title="SSL Verification Disabled",
        pattern=re.compile(r'verify\s*=\s*False'),
        severity=Severity.HIGH,
        description="Disabling SSL certificate verification exposes connections to MITM attacks.",
        suggestion="Remove verify=False. If using a custom CA, pass verify='/path/to/ca-bundle.crt'.",
        cwe="CWE-295",
    ),
]


# ─────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────

class Scanner:
    """
    Main scanning engine. Runs static rules then optionally invokes
    an LLM client for a deeper contextual review.
    """

    def __init__(self, llm_client: LLMClient | None = None):
        self._llm = llm_client or MockLLMClient()

    def scan_code(
        self,
        code: str,
        filename: str = "<stdin>",
        language: str = "python",
        use_llm: bool = True,
    ) -> ScanResult:
        import time

        t0 = time.perf_counter()

        findings: list[Vulnerability] = []
        rules = PYTHON_RULES if language == "python" else []
        lines = code.splitlines()

        for i, line in enumerate(lines, start=1):
            for rule in rules:
                if rule.pattern.search(line):
                    findings.append(
                        Vulnerability(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            description=rule.description,
                            severity=rule.severity,
                            file=filename,
                            line=i,
                            snippet=line.strip()[:120],
                            suggestion=rule.suggestion,
                            cwe=rule.cwe,
                        )
                    )

        # Sort: most severe first
        findings.sort(key=lambda v: SEVERITY_SCORE[v.severity], reverse=True)

        llm_summary = ""
        if use_llm:
            llm_summary = self._llm.review(code, findings)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return ScanResult(
            file=filename,
            language=language,
            vulnerabilities=findings,
            llm_summary=llm_summary,
            scan_time_ms=round(elapsed_ms, 2),
        )

    def scan_file(self, path: Path, use_llm: bool = True) -> ScanResult:
        code = path.read_text(encoding="utf-8", errors="replace")
        lang = _detect_language(path)
        return self.scan_code(code, filename=str(path), language=lang, use_llm=use_llm)

    def scan_directory(
        self, directory: Path, use_llm: bool = True, extensions: tuple[str, ...] = (".py",)
    ) -> list[ScanResult]:
        results = []
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix in extensions:
                results.append(self.scan_file(path, use_llm=use_llm))
        return results


def _detect_language(path: Path) -> str:
    mapping = {".py": "python", ".js": "javascript", ".ts": "typescript"}
    return mapping.get(path.suffix, "unknown")
