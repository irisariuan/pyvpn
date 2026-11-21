"""Small Linux network-namespace exec helper for isolated policies."""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import NoReturn


class NetworkNamespaceUnavailable(RuntimeError):
    """Network namespace isolation is unavailable on this kernel/runtime."""


def enter_network_namespace() -> None:
    """Create a private network namespace for the calling process."""
    unshare = getattr(os, "unshare", None)
    if not callable(unshare):
        raise NetworkNamespaceUnavailable("os.unshare is unavailable on this platform")
    clone_newnet = getattr(os, "CLONE_NEWNET", 0x40000000)
    try:
        unshare(clone_newnet)
    except OSError as exc:
        raise NetworkNamespaceUnavailable(f"cannot create network namespace: {exc}") from exc


def exec_isolated(command: Sequence[str]) -> NoReturn:
    """Enter a new network namespace and replace the process with command.

    Namespace interface setup and routing remain the daemon's responsibility;
    this helper intentionally does not configure host networking.
    """
    if not command:
        raise ValueError("a command is required")
    enter_network_namespace()
    os.execvp(command[0], list(command))
    raise AssertionError("execvp returned")
