"""OpenAI ChatCompletion backend with exponential-backoff retry."""
from __future__ import annotations

import time

from securelens.exceptions import LLMTimeoutError
from securelens.scanner import Vulnerability

_SYSTEM_PROMPT = """\
You are an expert application security engineer reviewing source code.
You will receive static-analysis findings and the source code.
Provide a concise (3-5 sentence) security assessment that confirms or
contextualises the findings, surfaces any additional risks, and recommends
prioritised remediation. Reply in plain text with no markdown headings."""


def _build_messages(code: str, findings: list[Vulnerability]) -> list[dict]:
    if findings:
        findings_text = "\n".join(
            f"- [{v.rule_id}] {v.title} (line {v.line}, {v.severity.value}): {v.description}"
            for v in findings
        )
    else:
        findings_text = "No static findings."
    user_content = (
        f"Static findings:\n{findings_text}\n\n"
        f"Source code:\n```\n{code}\n```"
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


class OpenAIClient:
    """OpenAI ChatCompletion backend.

    Retries on transient API errors with exponential back-off.
    Install the SDK with: pip install 'securelens[openai]'
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        try:
            import openai as _openai
        except ImportError as exc:
            raise ImportError(
                "OpenAI SDK not found. Install it with: "
                "pip install 'securelens[openai]'"
            ) from exc
        self._client = _openai.OpenAI(api_key=api_key, timeout=timeout)
        self._model = model
        self._timeout = timeout
        self._max_retries = max_retries

    def review(self, code: str, static_findings: list[Vulnerability]) -> str:
        import openai

        messages = _build_messages(code, static_findings)

        for attempt in range(self._max_retries):
            try:
                response = self._client.chat.completions.create(
                    model=self._model,
                    messages=messages,
                    max_tokens=512,
                    temperature=0.2,
                )
                return response.choices[0].message.content or ""

            except openai.APITimeoutError as exc:
                if attempt == self._max_retries - 1:
                    raise LLMTimeoutError("openai", self._timeout) from exc
                time.sleep(2**attempt)

            except openai.RateLimitError:
                if attempt == self._max_retries - 1:
                    raise
                time.sleep(2 ** (attempt + 1))

            except openai.APIError:
                raise  # non-retriable

        raise RuntimeError("Unreachable")  # pragma: no cover
