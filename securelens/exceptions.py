class SecureLensError(Exception):
    """Base exception for all SecureLens errors."""


class FileTooLargeError(SecureLensError):
    def __init__(self, path: str, size: int, limit: int) -> None:
        self.path = path
        self.size = size
        self.limit = limit
        super().__init__(
            f"File '{path}' ({size:,} bytes) exceeds the {limit:,}-byte scan limit."
        )


class UnsupportedLanguageError(SecureLensError):
    def __init__(self, language: str) -> None:
        self.language = language
        super().__init__(f"No scanner is available for language '{language}'.")


class LLMTimeoutError(SecureLensError):
    def __init__(self, provider: str, timeout: int) -> None:
        self.provider = provider
        self.timeout = timeout
        super().__init__(
            f"LLM provider '{provider}' did not respond within {timeout} seconds."
        )


class RuleLoadError(SecureLensError):
    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"Failed to load rules from '{path}': {reason}")
