# 🔍 SecureLens

**AI-powered code vulnerability reviewer with CI/CD integration**

[![CI](https://github.com/Alisid07/securelens/actions/workflows/ci.yml/badge.svg)](https://github.com/Alisid07/securelens/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SecureLens combines a fast static rule engine with an LLM review layer to surface security vulnerabilities in Python codebases. It ships as a CLI tool, a REST API, and a CI/CD gate — and the LLM backend is fully swappable (OpenAI, Anthropic, or the built-in offline stub).

---

## Features

- **10 built-in security rules** covering OWASP Top 10 patterns (hardcoded secrets, SQL injection, insecure deserialization, weak hashing, and more)
- **LLM review layer** — pluggable architecture; swap in OpenAI GPT-4, Anthropic Claude, or run offline with the mock stub
- **Three report formats** — JSON (CI-friendly), Markdown (PR comments), SARIF (GitHub Advanced Security)
- **FastAPI web service** — scan code snippets via REST API
- **CI/CD gate** — `--fail-on HIGH` exits with code 1 to block deployments
- **Zero required dependencies** — core engine is pure Python stdlib; web/LLM extras are optional

---

## Quick Start

```bash
git clone https://github.com/Alisid07/securelens.git
cd securelens

# Scan a single file
python -m securelens scan examples/example_vulnerable.py

# Scan a directory
python -m securelens scan ./src

# Output a Markdown report
python -m securelens scan ./src --format markdown --output report.md

# Output SARIF for GitHub code scanning
python -m securelens scan ./src --format sarif --output results.sarif

# Block CI if any CRITICAL or HIGH findings exist
python -m securelens scan ./src --fail-on HIGH
```

---

## Example Output

```
SecureLens — Scan Complete
──────────────────────────────────────────────────
  Files scanned      : 1
  Vulnerabilities    : 10
  Total risk score   : 67

  examples/example_vulnerable.py  [FAIL]  score=67
    [CRITICAL]  L6   Hardcoded Secret  (PY001)
               → Use environment variables or a secrets manager
    [HIGH]      L14  Shell Injection via os.system  (PY003)
               → Use subprocess.run() with shell=False
    [HIGH]      L20  SQL Injection Risk  (PY002)
               → Use parameterised queries
    [HIGH]      L25  eval() Usage  (PY005)
               → Replace eval() with ast.literal_eval()
    ...

    🤖 AI: The code contains 10 static finding(s). The most critical
           concern is Hardcoded Secret. Recommend applying the
           principle of least privilege and validating all external
           inputs before processing.
──────────────────────────────────────────────────
```

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  SecureLens                      │
│                                                  │
│  ┌──────────┐    ┌──────────────────────────┐   │
│  │   CLI    │    │       FastAPI REST        │   │
│  │  (cli.py)│    │        (api.py)           │   │
│  └────┬─────┘    └────────────┬─────────────┘   │
│       │                       │                  │
│       └──────────┬────────────┘                  │
│                  ▼                               │
│         ┌────────────────┐                       │
│         │   Scanner      │                       │
│         │  (scanner.py)  │                       │
│         └───┬────────────┘                       │
│             │                                    │
│     ┌───────┴────────┐                           │
│     ▼                ▼                           │
│  Static Rules    LLM Client                      │
│  (10 regex +     (MockLLMClient / OpenAI /       │
│   AST patterns)   Anthropic — swappable)         │
│                                                  │
│         ┌────────────────┐                       │
│         │   Reporter     │                       │
│         │ JSON│MD│SARIF  │                       │
│         └────────────────┘                       │
└─────────────────────────────────────────────────┘
```

---

## Plugging in a Real LLM

The `LLMClient` protocol is a single method: `review(code, findings) -> str`.
Swap the backend without changing any other code:

```python
# openai_client.py
import openai
from securelens.scanner import Vulnerability

class OpenAIClient:
    def __init__(self, model: str = "gpt-4o"):
        self.client = openai.OpenAI()
        self.model = model

    def review(self, code: str, findings: list[Vulnerability]) -> str:
        finding_summary = "\n".join(
            f"- {v.severity.value} [{v.rule_id}] {v.title} at line {v.line}"
            for v in findings
        )
        prompt = (
            f"You are a security engineer. Review this Python code for vulnerabilities.\n\n"
            f"Static analysis already found:\n{finding_summary}\n\n"
            f"Code:\n```python\n{code[:3000]}\n```\n\n"
            f"Provide a concise security assessment and recommended actions."
        )
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400,
        )
        return response.choices[0].message.content

# Usage
from securelens.scanner import Scanner

scanner = Scanner(llm_client=OpenAIClient())
result = scanner.scan_file(Path("app.py"))
```

---

## Web API

```bash
pip install securelens[web]
uvicorn securelens.api:app --reload --port 8000
```

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"secret123\"\neval(user_input)",
    "filename": "app.py",
    "use_llm": true
  }'
```

Response:
```json
{
  "file": "app.py",
  "language": "python",
  "risk_score": 17,
  "passed": false,
  "vulnerabilities": [
    {
      "rule_id": "PY001",
      "title": "Hardcoded Secret",
      "severity": "CRITICAL",
      "line": 1,
      "cwe": "CWE-798",
      ...
    }
  ],
  "llm_summary": "..."
}
```

---

## CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: SecureLens security scan
  run: |
    python -m securelens scan ./src --format sarif --output results.sarif
    python -m securelens scan ./src --fail-on HIGH

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Built-in Rules

| ID    | Severity | CWE      | Description                          |
|-------|----------|----------|--------------------------------------|
| PY001 | CRITICAL | CWE-798  | Hardcoded credentials/secrets        |
| PY002 | HIGH     | CWE-89   | SQL injection via string formatting  |
| PY003 | HIGH     | CWE-78   | Shell injection via `os.system()`    |
| PY004 | HIGH     | CWE-502  | Unsafe deserialization (`pickle`)    |
| PY005 | HIGH     | CWE-95   | Arbitrary code execution (`eval()`)  |
| PY006 | MEDIUM   | CWE-327  | Broken cryptography (MD5, SHA-1)     |
| PY007 | MEDIUM   | CWE-215  | Debug mode enabled in production     |
| PY009 | MEDIUM   | CWE-338  | Insecure randomness (`random`)       |
| PY010 | HIGH     | CWE-295  | SSL verification disabled            |
| PY008 | LOW      | CWE-390  | Broad exception suppression          |

---

## Project Structure

```
securelens/
├── securelens/
│   ├── __init__.py        # package metadata
│   ├── scanner.py         # core engine: rules, Scanner, LLMClient protocol
│   ├── reporter.py        # JSON / Markdown / SARIF output
│   ├── cli.py             # command-line interface
│   ├── api.py             # FastAPI web service
│   └── __main__.py        # python -m securelens entrypoint
├── tests/
│   └── test_scanner.py    # pytest test suite (25 tests)
├── examples/
│   ├── example_vulnerable.py   # intentionally insecure demo file
│   └── example_safe.py         # secure refactored counterpart
├── .github/workflows/
│   └── ci.yml             # GitHub Actions: test + self-scan + SARIF upload
├── pyproject.toml
└── README.md
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Roadmap

- [ ] JavaScript / TypeScript rule engine
- [ ] Dependency vulnerability scanning (CVE database lookup)
- [ ] GitHub PR comment integration
- [ ] VS Code extension
- [ ] Support for Anthropic Claude as LLM backend
- [ ] Custom rule definition via YAML config

---

## License

MIT — see [LICENSE](LICENSE) for details.
