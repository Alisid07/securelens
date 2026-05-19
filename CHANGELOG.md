# Changelog

All notable changes to SecureLens are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `securelens/config.py` — `Settings` dataclass backed by environment variables;
  `get_settings()` / `reset_settings()` helpers.
- `securelens/exceptions.py` — typed exception hierarchy:
  `SecureLensError`, `FileTooLargeError`, `UnsupportedLanguageError`,
  `LLMTimeoutError`, `RuleLoadError`.
- `securelens/rules/loader.py` — `load_rules()` loads `Rule` objects from YAML
  files; raises `RuleLoadError` with a descriptive message on failure.
- `securelens/rules/python_rules.yaml` — YAML definitions for all 12 Python rules
  (PY001–PY010 existing + PY011 path traversal + PY012 SSRF).
- `securelens/llm/` package — pluggable LLM backend architecture:
  - `base.py` — `LLMClient` Protocol.
  - `mock_client.py` — deterministic offline stub (no API key required).
  - `anthropic_client.py` — Anthropic Claude backend with exponential-backoff retry.
  - `openai_client.py` — OpenAI ChatCompletion backend with exponential-backoff retry.
  - `__init__.py` — `create_llm_client()` factory that reads `SECURELENS_LLM_PROVIDER`.
- `securelens/languages/python/scanner.py` — `PythonASTScanner` with two-pass
  scanning: regex (pass 1) + AST walk (pass 2) for `subprocess shell=True` (PY101),
  `assert` for security (PY102), mutable defaults (PY103).
- `securelens/languages/javascript/scanner.py` — `JavaScriptScanner` with 12
  regex-based rules (JS001–JS012) covering XSS, SSRF, prototype pollution, etc.
- `reporter.generate_html()` — standalone HTML report with embedded CSS,
  summary cards, per-file findings, colour-coded severity badges, and AI review.
- `.env` — template for all supported environment variables.
- `.github/dependabot.yml` — automated dependency updates for pip and GitHub Actions.

### Changed
- `reporter.ReportFormat` now includes `"html"` and `write_report()` dispatches
  to `generate_html()` for that format.

---

## [0.1.0] — 2024-07-01

### Added
- Initial release with 10 Python static-analysis rules (PY001–PY010).
- JSON, Markdown, and SARIF report formats.
- Mock LLM client for offline use.
- CLI with `scan` and `rules` subcommands.
- `--fail-on` CI gate flag.
- GitHub Actions workflow for matrix testing on Python 3.10–3.12.

[Unreleased]: https://github.com/Alisid07/securelens/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Alisid07/securelens/releases/tag/v0.1.0
