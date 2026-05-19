# Contributing to SecureLens

Thank you for your interest in contributing!
This document describes how to set up a development environment, run the test
suite, write new security rules, and submit a pull request.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Project Layout](#project-layout)
3. [Running Tests](#running-tests)
4. [Writing a New Rule](#writing-a-new-rule)
5. [Adding an LLM Backend](#adding-an-llm-backend)
6. [Code Style](#code-style)
7. [Pull Request Guidelines](#pull-request-guidelines)
8. [Reporting Bugs](#reporting-bugs)

---

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/Alisid07/securelens.git
cd securelens

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install in editable mode with all dev extras
pip install -e ".[dev,anthropic,openai,web]"

# 4. Copy the environment template
cp .env.example .env   # then fill in any keys you need
```

---

## Project Layout

```
securelens/
├── config.py                   # Settings (env-var backed)
├── exceptions.py               # Typed exception hierarchy
├── scanner.py                  # Core models (Severity, Vulnerability, ScanResult, Rule)
├── reporter.py                 # JSON / Markdown / SARIF / HTML report generators
├── cli.py                      # Command-line interface
├── rules/
│   ├── loader.py               # YAML rule loader
│   ├── python_rules.yaml       # Built-in Python rules (PY001–PY012)
│   └── javascript_rules.yaml   # Built-in JavaScript rules (JS001–JS012)
├── llm/
│   ├── base.py                 # LLMClient Protocol
│   ├── mock_client.py          # Offline stub
│   ├── anthropic_client.py     # Anthropic Claude backend
│   └── openai_client.py        # OpenAI ChatCompletion backend
└── languages/
    ├── python/scanner.py       # Two-pass AST + regex scanner
    └── javascript/scanner.py   # Regex-based JS/TS scanner
```

---

## Running Tests

```bash
# All tests with coverage
pytest --cov=securelens --cov-report=term-missing

# Specific test file
pytest tests/test_scanner.py -v

# Linting
ruff check securelens tests

# Type-checking
mypy securelens
```

The test suite must pass on Python 3.10, 3.11, and 3.12 before a PR is merged.

---

## Writing a New Rule

### Option A — YAML (recommended for simple regex rules)

Add an entry to `securelens/rules/python_rules.yaml` (or create a new YAML
file and load it via `load_rules()`):

```yaml
- id: PY013
  title: My New Rule
  severity: HIGH          # CRITICAL | HIGH | MEDIUM | LOW | INFO
  cwe: CWE-XXX
  pattern: |-
    regex_pattern_here
  description: >-
    What risk this detects and why it matters.
  suggestion: >-
    How to fix the issue.
```

Run `python -m securelens rules` to verify the rule loads correctly.

### Option B — AST check (for context-aware Python rules)

Add a `visit_*` method or a private check method to `_SecurityVisitor` in
`securelens/languages/python/scanner.py`, appending to `self.findings` with:

```python
self.findings.append((
    node,       # AST node (used to get line number)
    "PY999",    # rule_id
    "Title",    # title
    "CWE-XXX",  # cwe
    Severity.HIGH,
    "Description of the risk.",
    "Remediation suggestion.",
))
```

### Rule ID namespaces

| Prefix | Language     | Range       |
|--------|--------------|-------------|
| PY     | Python       | PY001–PY199 |
| JS     | JavaScript   | JS001–JS099 |
| TS     | TypeScript   | TS001–TS099 |
| GEN    | Language-agnostic | GEN001+ |

---

## Adding an LLM Backend

1. Create `securelens/llm/<provider>_client.py` with a class that satisfies the
   `LLMClient` protocol (implements `review(code, static_findings) -> str`).
2. Add a branch to `create_llm_client()` in `securelens/llm/__init__.py`.
3. Add the provider SDK as an optional extra in `pyproject.toml`.
4. Document the new `SECURELENS_LLM_PROVIDER` value in `.env.example`.

---

## Code Style

- **Formatter / linter**: [Ruff](https://docs.astral.sh/ruff/) (`ruff check --fix`)
- **Type hints**: required for all public functions and methods
- **Docstrings**: one-line summary only for public symbols; skip for private helpers
- **Comments**: only when the _why_ is non-obvious
- **No new dependencies** in the core package without discussion; keep optional extras in `pyproject.toml`

---

## Pull Request Guidelines

1. Branch from `main` with a descriptive name: `feat/py013-command-injection`,
   `fix/html-report-escaping`, etc.
2. Keep PRs focused — one logical change per PR.
3. Add or update tests; coverage must not drop.
4. Run `ruff check` and `mypy` locally before pushing.
5. Reference any related issue in the PR description.
6. Update `CHANGELOG.md` under `[Unreleased]`.

---

## Reporting Bugs

Please open an issue at
[github.com/Alisid07/securelens/issues](https://github.com/Alisid07/securelens/issues)
and include:

- SecureLens version (`pip show securelens`)
- Python version (`python --version`)
- Minimal code sample that triggers the bug
- Expected vs. actual output
