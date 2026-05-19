"""LLM backend factory and public re-exports."""
from __future__ import annotations

from securelens.llm.base import LLMClient
from securelens.llm.mock_client import MockLLMClient


def create_llm_client(provider: str | None = None) -> LLMClient:
    """Return an LLM client for *provider*, falling back to the value in Settings.

    Supported providers: ``"mock"`` (default), ``"anthropic"``, ``"openai"``.
    Lazy-imports the provider SDK so the core package stays dependency-free.
    """
    from securelens.config import get_settings

    settings = get_settings()
    resolved = provider or settings.llm_provider

    if resolved == "anthropic":
        from securelens.llm.anthropic_client import AnthropicClient

        return AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.llm_model,
            timeout=settings.llm_timeout,
            max_retries=settings.llm_max_retries,
        )

    if resolved == "openai":
        from securelens.llm.openai_client import OpenAIClient

        return OpenAIClient(
            api_key=settings.openai_api_key,
            model=settings.llm_model,
            timeout=settings.llm_timeout,
            max_retries=settings.llm_max_retries,
        )

    return MockLLMClient()


__all__ = ["create_llm_client", "LLMClient", "MockLLMClient"]
