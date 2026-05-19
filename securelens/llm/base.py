from __future__ import annotations

from typing import Protocol, runtime_checkable

from securelens.scanner import Vulnerability


@runtime_checkable
class LLMClient(Protocol):
    """Structural interface every SecureLens LLM backend must satisfy.

    Any object that implements ``review`` with the correct signature is
    accepted — no explicit subclassing is required.
    """

    def review(self, code: str, static_findings: list[Vulnerability]) -> str:
        """Return a plain-text security analysis of *code*.

        *static_findings* contains the Vulnerability objects already produced
        by the static rule engine so the LLM can augment rather than duplicate
        them.
        """
        ...
