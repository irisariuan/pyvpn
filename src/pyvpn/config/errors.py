"""Clear configuration errors for Stream A callers."""

from __future__ import annotations

from collections.abc import Iterable


class ConfigError(Exception):
    """base class for configuration loading and validation failures."""


class ConfigFileError(ConfigError):
    """configuration could not be read or parsed."""


class ConfigValidationError(ConfigError):
    """configuration parsed but failed migration or model validation."""

    def __init__(self, message: str, problems: Iterable[str] = ()) -> None:
        super().__init__(message)
        self.message = message
        self.problems = tuple(problems)
