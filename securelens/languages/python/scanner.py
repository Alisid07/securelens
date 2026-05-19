"""Two-pass Python security scanner (regex + AST)."""
from __future__ import annotations

import ast
import time
from pathlib import Path

from securelens.config import get_settings
from securelens.exceptions import FileTooLargeError
from securelens.scanner import (
    PYTHON_RULES,
    Rule,
    ScanResult,
    Severity,
    Vulnerability,
)

_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class PythonASTScanner:
    """Scans Python source in two passes:

    Pass 1 — regex rules applied line-by-line (fast; catches most patterns).
    Pass 2 — AST walk for context-aware checks that regex cannot express
              reliably (e.g. subprocess with shell=True, unsafe asserts,
              mutable default arguments).
    """

    def __init__(self, extra_rules: list[Rule] | None = None) -> None:
        self._rules = PYTHON_RULES + (extra_rules or [])
        self._settings = get_settings()

    # ─── Public API ──────────────────────────────────────────

    def scan_file(self, path: Path) -> ScanResult:
        size = path.stat().st_size
        if size > self._settings.max_file_size:
            raise FileTooLargeError(str(path), size, self._settings.max_file_size)
        code = path.read_text(encoding="utf-8", errors="replace")
        return self.scan_code(code, filename=str(path))

    def scan_code(self, code: str, filename: str = "<stdin>") -> ScanResult:
        t0 = time.perf_counter()

        findings: list[Vulnerability] = []
        findings.extend(self._regex_pass(code, filename))
        findings.extend(self._ast_pass(code, filename))

        # Stable sort: highest severity first, then by line number
        findings.sort(key=lambda v: (-_SEVERITY_RANK[v.severity], v.line))

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return ScanResult(
            file=filename,
            language="python",
            vulnerabilities=findings,
            scan_time_ms=elapsed_ms,
        )

    # ─── Pass 1: regex ───────────────────────────────────────

    def _regex_pass(self, code: str, filename: str) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
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
                            snippet=line.strip()[:120],
                            suggestion=rule.suggestion,
                            cwe=rule.cwe,
                        )
                    )
        return findings

    # ─── Pass 2: AST ─────────────────────────────────────────

    def _ast_pass(self, code: str, filename: str) -> list[Vulnerability]:
        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError:
            return []

        lines = code.splitlines()
        visitor = _SecurityVisitor()
        visitor.visit(tree)

        findings: list[Vulnerability] = []
        for node, rule_id, title, cwe, severity, desc, suggestion in visitor.findings:
            lineno = getattr(node, "lineno", 0)
            snippet = (
                lines[lineno - 1].strip()[:120]
                if lineno and lineno <= len(lines)
                else ""
            )
            findings.append(
                Vulnerability(
                    rule_id=rule_id,
                    title=title,
                    description=desc,
                    severity=severity,
                    file=filename,
                    line=lineno,
                    snippet=snippet,
                    suggestion=suggestion,
                    cwe=cwe,
                )
            )
        return findings


# ─── AST visitor ─────────────────────────────────────────────

class _SecurityVisitor(ast.NodeVisitor):
    """Collects AST-level security findings as (node, rule_id, …) tuples."""

    def __init__(self) -> None:
        # Each entry: (node, rule_id, title, cwe, severity, description, suggestion)
        self.findings: list[tuple] = []

    def visit_Call(self, node: ast.Call) -> None:
        self._check_subprocess_shell(node)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self._check_assert_security(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_mutable_default(node)
        self.generic_visit(node)

    # AsyncFunctionDef shares the same default-arg risk
    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # ── Individual checks ────────────────────────────────────

    def _check_subprocess_shell(self, node: ast.Call) -> None:
        """Flag subprocess calls where shell=True is explicitly set."""
        func = node.func
        is_subprocess_call = isinstance(func, ast.Attribute) and isinstance(
            func.value, ast.Name
        ) and func.value.id == "subprocess"
        is_bare_call = isinstance(func, ast.Name) and func.id in {
            "run", "Popen", "call", "check_call", "check_output"
        }
        if not (is_subprocess_call or is_bare_call):
            return
        for kw in node.keywords:
            if (
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                self.findings.append((
                    node,
                    "PY101",
                    "subprocess with shell=True",
                    "CWE-78",
                    Severity.HIGH,
                    "subprocess called with shell=True allows shell injection via string arguments.",
                    "Pass arguments as a list and set shell=False (the default).",
                ))

    def _check_assert_security(self, node: ast.Assert) -> None:
        """Flag assert statements used for authentication/authorisation checks.

        assert is stripped by the interpreter with python -O so it must never
        be relied on for security enforcement.
        """
        src = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
        _SECURITY_KEYWORDS = (
            "auth", "permission", "is_admin", "is_authenticated",
            "user", "role", "token", "access",
        )
        if any(kw in src.lower() for kw in _SECURITY_KEYWORDS):
            self.findings.append((
                node,
                "PY102",
                "assert Used for Security Check",
                "CWE-617",
                Severity.MEDIUM,
                (
                    "assert statements are removed when Python runs with -O; "
                    "never rely on them for access control or authentication."
                ),
                "Replace with an explicit if/raise guard.",
            ))

    def _check_mutable_default(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Flag mutable default arguments (list, dict, set literals)."""
        mutable = (ast.List, ast.Dict, ast.Set)
        all_defaults = node.args.defaults + [
            d for d in node.args.kw_defaults if d is not None
        ]
        for default in all_defaults:
            if isinstance(default, mutable):
                self.findings.append((
                    node,
                    "PY103",
                    "Mutable Default Argument",
                    "",
                    Severity.INFO,
                    (
                        "Mutable default arguments are shared across all calls; "
                        "mutations in one call affect subsequent calls."
                    ),
                    "Use None as the default and initialise inside the function body.",
                ))
                break  # one finding per function is enough
