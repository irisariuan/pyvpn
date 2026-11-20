"""Unprivileged ``pyvpn run`` daemon hand-off and exec helpers."""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Sequence
from pathlib import Path
from typing import Literal, NoReturn

from pyvpn.constants import SOCKET_PATH


class DaemonUnavailable(RuntimeError):
    """The pyvpn daemon could not accept the placement request."""


def request_place_pid(
    policy: str | int,
    *,
    pid: int | None = None,
    socket_path: str | Path = SOCKET_PATH,
    timeout: float = 2.0,
) -> None:
    """Ask the daemon to place this process in the requested policy cgroup."""
    process_id = os.getpid() if pid is None else pid
    if process_id != os.getpid():
        raise ValueError("an unprivileged launcher may only place its own PID")
    request = {"id": 1, "method": "place_pid", "params": {"pid": process_id, "policy": policy}}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(socket_path))
            client.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode())
            stream = client.makefile("rb")
            response = stream.readline(64 * 1024 + 1)
    except OSError as exc:
        raise DaemonUnavailable(f"cannot contact pyvpn daemon: {exc}") from exc
    if not response or len(response) > 64 * 1024:
        raise DaemonUnavailable("daemon returned an empty or oversized response")
    try:
        result = json.loads(response)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DaemonUnavailable("daemon returned an invalid response") from exc
    if result.get("id") != 1 or result.get("ok") is not True:
        error = result.get("error") or {}
        raise DaemonUnavailable(str(error.get("message", "daemon rejected placement")))


def run(
    policy: str | int,
    command: Sequence[str],
    *,
    socket_path: str | Path = SOCKET_PATH,
    isolation: Literal["none", "netns"] = "none",
) -> NoReturn:
    """Place this process, then replace it with ``command`` via execvp."""
    if not command:
        raise ValueError("a command is required")
    request_place_pid(policy, socket_path=socket_path)
    if isolation == "netns":
        from pyvpn.apps.netns import enter_network_namespace

        enter_network_namespace()
    os.execvp(command[0], list(command))
    raise AssertionError("execvp returned")
