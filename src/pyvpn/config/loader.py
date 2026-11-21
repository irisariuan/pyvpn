"""Load pyvpn JSON configuration from disk or text."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from pyvpn.config.errors import ConfigFileError, ConfigValidationError
from pyvpn.config.migrations import migrate_config
from pyvpn.config.models import Config

DEFAULT_CONFIG_PATH: Final = Path("/etc/pyvpn/config.json")
CONFIG_ENV: Final = "PYVPN_CONFIG"


def default_config_path() -> Path:
    """return the configured path or the system default."""
    return Path(os.environ.get(CONFIG_ENV, DEFAULT_CONFIG_PATH))


def load_config_text(text: str, source: str = "<string>") -> Config:
    """parse, migrate, and validate a JSON configuration string."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigFileError(
            f"{source}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    return validate_config_document(document, source)


def validate_config_document(document: object, source: str = "<object>") -> Config:
    """migrate and validate one decoded configuration document."""
    migrated = migrate_config(document)
    try:
        return Config.model_validate(migrated)
    except ValidationError as exc:
        problems = [
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_url=False)
        ]
        raise ConfigValidationError(
            f"{source}: configuration validation failed",
            problems,
        ) from exc


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """load and validate a JSON configuration file."""
    config_path = Path(path) if path is not None else default_config_path()
    try:
        text = config_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigFileError(f"configuration file not found: {config_path}") from exc
    except PermissionError as exc:
        raise ConfigFileError(f"cannot read configuration file: {config_path}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigFileError(f"{config_path}: configuration is not valid UTF-8") from exc
    except OSError as exc:
        raise ConfigFileError(f"cannot read configuration file: {config_path}: {exc}") from exc

    return load_config_text(text, str(config_path))
