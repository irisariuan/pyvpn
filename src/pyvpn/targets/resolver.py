"""Interface-name resolution for target configurations."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable


def resolve_interface(pattern: str, interface_names: Iterable[str]) -> str | None:
    """Resolve an exact interface name or glob to one interface.

    Exact names take precedence.  Glob matches are sorted for deterministic
    behaviour when multiple interfaces match a pattern.
    """

    names = tuple(interface_names)
    if pattern in names:
        return pattern

    matches = sorted(name for name in names if fnmatch.fnmatchcase(name, pattern))
    return matches[0] if matches else None


def resolve_interfaces(pattern: str, interface_names: Iterable[str]) -> tuple[str, ...]:
    """Return all matching interface names deterministically."""

    names = tuple(interface_names)
    if pattern in names:
        return (pattern,)
    return tuple(sorted(name for name in names if fnmatch.fnmatchcase(name, pattern)))
