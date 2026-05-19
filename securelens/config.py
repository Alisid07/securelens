from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    # Which LLM backend to use: "mock" | "anthropic" | "openai"
    llm_provider: str = field(
        default_factory=lambda: os.getenv("SECURELENS_LLM_PROVIDER", "mock")
    )
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )
    openai_api_key: str = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "")
    )
    llm_model: str = field(
        default_factory=lambda: os.getenv("SECURELENS_LLM_MODEL", "claude-sonnet-4-6")
    )
    llm_timeout: int = field(
        default_factory=lambda: int(os.getenv("SECURELENS_LLM_TIMEOUT", "30"))
    )
    llm_max_retries: int = field(
        default_factory=lambda: int(os.getenv("SECURELENS_LLM_MAX_RETRIES", "3"))
    )
    # Maximum file size accepted by scanners (bytes); default 1 MiB
    max_file_size: int = field(
        default_factory=lambda: int(
            os.getenv("SECURELENS_MAX_FILE_SIZE", str(1 * 1024 * 1024))
        )
    )
    # Directory containing YAML rule files
    rules_dir: Path = field(
        default_factory=lambda: Path(
            os.getenv(
                "SECURELENS_RULES_DIR",
                str(Path(__file__).parent / "rules"),
            )
        )
    )


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Force re-read from environment; useful in tests that patch os.environ."""
    global _settings
    _settings = None
