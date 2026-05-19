"""Anthropic Claude backend with exponential-backoff retry."""
from __future__ import annotations

import time

from securelens.exceptions import LLMTimeoutError
from securelens.scanner import Vulnerability

_SYSTEM_PROMPT = """\
You are an expert application security engineer reviewing Python source code.
You will receive the source code and a list of static-analysis findings.
Provide a concise (3-5 sentence) security assessment that:
1. Confirms or contextualises the static findings.
2. Identifies additional risks not caught by static analysis.
3. Recommends prioritised remediation steps.
Reply in plain text with no markdown headings or bullet formatting."""


def _build_user_message(code: str, findings: list[Vulnerability]) -> str:
    if findings:
        findings_text = "\n".join(
            f"- [{v.rule_id}] {v.title} (line {v.line}, {v.severity.value}): {v.description}"
            for v in findings
        )
    else:
        findings_text = "No static findings."
    return (
        f"Static findings:\n{findings_text}\n\n"
        f"Source code:\n```python\n{code}\n```"
    )


class AnthropicClient:
    """Anthropic Claude backend.

    Retries on transient API errors with exponential back-off.
    Install the SDK with: pip install 'securelens[anthropic]'
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-6",
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        try:
            import anthropic as _anthropic
        except ImportError as exc:
            raise ImportError(
                "Anthropic SDK not found. Install it with: "
                "pip install 'securelens[anthropic]'"
            ) from exc
        self._client = _anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._timeout = timeout
        self._max_retries = max_retries

    def review(self, code: str, static_findings: list[Vulnerability]) -> str:
        import anthropic

        user_msg = _build_user_message(code, static_findings)

        for attempt in range(self._max_retries):
            try:
                response = self._client.messages.create(
                    model=self._model,
                    max_tokens=512,
                    system=_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_msg}],
                    timeout=self._timeout,
                )
                return response.content[0].text

            except anthropic.APITimeoutError as exc:
                if attempt == self._max_retries - 1:
                    raise LLMTimeoutError("anthropic", self._timeout) from exc
                time.sleep(2**attempt)

            except anthropic.RateLimitError:
                if attempt == self._max_retries - 1:
                    raise
                time.sleep(2 ** (attempt + 1))

            except anthropic.APIError:
                raise  # non-retriable (auth, bad request, etc.)

        raise RuntimeError("Unreachable")  # pragma: no cover
