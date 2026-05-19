from __future__ import annotations

import hashlib
import random

from securelens.scanner import Vulnerability


class MockLLMClient:
    """Offline stub — deterministic responses without an API key.

    Useful in tests, CI runs without secrets, and ``--no-llm`` mode.
    Replace with AnthropicClient or OpenAIClient for real reviews.
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
        seed = int(hashlib.md5(code[:64].encode()).hexdigest(), 16)
        rng = random.Random(seed)
        n = len(static_findings)
        top_issue = static_findings[0].title if static_findings else "no issues detected"
        return rng.choice(self._TEMPLATES).format(n=n, top_issue=top_issue)
