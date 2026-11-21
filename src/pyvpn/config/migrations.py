"""Versioned configuration migrations."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from pyvpn.config.errors import ConfigValidationError

CURRENT_CONFIG_VERSION = 1


def migrate_config(document: object) -> dict[str, Any]:
    """convert a parsed JSON document to the current config shape."""
    if not isinstance(document, dict):
        raise ConfigValidationError("configuration must be a JSON object")

    migrated = deepcopy(document)
    version = migrated.get("version")

    # legacy documents omitted version; version 1 is their only supported meaning.
    if version is None:
        migrated["version"] = CURRENT_CONFIG_VERSION

    if isinstance(migrated["version"], bool) or not isinstance(migrated["version"], int):
        raise ConfigValidationError(
            "invalid configuration version",
            ("version must be the integer 1",),
        )

    if migrated["version"] != CURRENT_CONFIG_VERSION:
        raise ConfigValidationError(
            f"unsupported configuration version {migrated['version']}",
            (f"supported versions: {CURRENT_CONFIG_VERSION}",),
        )

    return migrated


def has_config_version(document: Mapping[str, object]) -> bool:
    """report whether a document explicitly declares a version."""
    return "version" in document
