# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Older versions are not supported. Please upgrade to the latest release.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security bug in SecureLens, please report it privately so we
can address it before disclosure.

### How to report

1. Email **ali10sarmad@gmail.com** with the subject line:
   `[SecureLens] Security Vulnerability Report`
2. Include:
   - A description of the vulnerability and its potential impact
   - Steps to reproduce (a minimal proof-of-concept is ideal)
   - Any relevant environment details (Python version, OS, SecureLens version)

We will acknowledge your report within **48 hours** and aim to release a fix
within **14 days** for critical issues.

### Coordinated disclosure

We follow a coordinated disclosure model. Please allow us a reasonable
remediation window before publishing any details publicly. We are happy to
credit you in the release notes if you wish.

---

## Security Design Notes

### No network access by default

SecureLens' core engine (static analysis) is entirely offline. No code, file
paths, or findings are transmitted anywhere unless you explicitly enable an LLM
backend with `SECURELENS_LLM_PROVIDER=anthropic` or `openai`.

### LLM data handling

When an LLM backend is enabled, the source code under scan and the static
findings are sent to the chosen provider's API. Review the relevant provider's
data-handling policy before scanning confidential code:

- Anthropic: https://www.anthropic.com/legal/privacy
- OpenAI:    https://openai.com/policies/privacy-policy

Use `--no-llm` (or `SECURELENS_LLM_PROVIDER=mock`) to disable this for
sensitive code bases.

### API key storage

API keys are read from environment variables or a `.env` file. The `.env` file
must never be committed to version control. The project's `.gitignore` excludes
`.env` by default.

### Rule YAML loading

Rules loaded from YAML use `yaml.safe_load`; arbitrary Python objects cannot be
instantiated through rule files.

---

## Scope

The following are in scope for security reports:

- Command injection via crafted filenames or scan targets
- Path traversal in file-scanning logic
- Remote code execution via crafted YAML rule files
- Information disclosure of scanned code to unintended parties
- Dependency vulnerabilities with a realistic exploit path in SecureLens

Out of scope:

- Vulnerabilities in LLM provider APIs (report those upstream)
- Denial-of-service via extremely large files (mitigated by `SECURELENS_MAX_FILE_SIZE`)
- Social-engineering attacks
