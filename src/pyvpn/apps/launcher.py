"""Unprivileged ``pyvpn run`` daemon hand-off and exec helpers."""

from __future__ import annotations

import contextlib
import json
import os
import select
import signal
import socket
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

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


Isolation = Literal["auto", "none", "netns"]
# Signals ``pyvpn run`` passes on to an isolated command, which is not in the
# terminal's process group (the daemon started it).
FORWARDED_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGUSR1", "SIGUSR2", "SIGWINCH")


class _Connection:
    """One JSON-lines connection to the daemon (several requests in turn)."""

    def __init__(self, socket_path: str | Path, timeout: float) -> None:
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(timeout)
        try:
            self._sock.connect(str(socket_path))
        except OSError as exc:
            self._sock.close()
            raise DaemonUnavailable(f"cannot contact pyvpn daemon: {exc}") from exc
        self._stream = self._sock.makefile("rb")
        self._next = 1

    def request(self, method: str, params: dict[str, Any], *, timeout: float | None = 2.0) -> Any:
        rid, self._next = self._next, self._next + 1
        line = json.dumps({"id": rid, "method": method, "params": params}, separators=(",", ":"))
        try:
            self._sock.settimeout(timeout)
            self._sock.sendall(line.encode() + b"\n")
            response = self._stream.readline(64 * 1024 + 1)
        except OSError as exc:
            raise DaemonUnavailable(f"lost the pyvpn daemon: {exc}") from exc
        if not response or len(response) > 64 * 1024:
            raise DaemonUnavailable("daemon returned an empty or oversized response")
        try:
            result = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DaemonUnavailable("daemon returned an invalid response") from exc
        if result.get("id") != rid or result.get("ok") is not True:
            error = result.get("error") or {}
            raise DaemonUnavailable(str(error.get("message", f"daemon rejected {method}")))
        return result.get("result")

    def close(self) -> None:
        self._stream.close()
        self._sock.close()


def policy_isolation(
    policy: str | int, *, socket_path: str | Path = SOCKET_PATH, timeout: float = 2.0
) -> str:
    """The configured isolation of a policy, as the daemon reports it."""
    conn = _Connection(socket_path, timeout)
    try:
        status = conn.request("status", {})
    finally:
        conn.close()
    for entry in status.get("policies", []) if isinstance(status, dict) else []:
        if entry.get("name") == policy or entry.get("id") == policy:
            return str(entry.get("isolation", "none"))
    raise DaemonUnavailable(f"no policy {policy!r}")


def run_isolated(
    policy: str | int,
    command: Sequence[str],
    *,
    socket_path: str | Path = SOCKET_PATH,
    timeout: float = 10.0,
) -> int:
    """Have the daemon start ``command`` in the policy's namespace; wait for it.

    The command runs as this user with this environment, working directory,
    umask and standard descriptors. Returns its exit status (128 + signal
    number when a signal ended it).
    """
    if not command:
        raise ValueError("a command is required")
    umask = os.umask(0)
    os.umask(umask)
    conn = _Connection(socket_path, timeout)
    try:
        started = conn.request(
            "run_isolated",
            {
                "policy": policy,
                "argv": list(command),
                "env": dict(os.environ),
                "cwd": os.getcwd(),
                "umask": umask,
            },
            timeout=timeout,
        )
        pid = int(started["pid"])
        pidfd: int | None = None
        with contextlib.suppress(OSError, AttributeError):
            pidfd = os.pidfd_open(pid)  # type: ignore[attr-defined,unused-ignore]
        previous = _forward_signals(pid, pidfd)
        try:
            try:
                done = conn.request("wait_isolated", {"pid": pid}, timeout=None)
            except DaemonUnavailable as exc:
                return _wait_without_daemon(pidfd, exc)
            code = int(done["returncode"])
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
            if pidfd is not None:
                os.close(pidfd)
    finally:
        conn.close()
    return 128 - code if code < 0 else code


def _forward_signals(pid: int, pidfd: int | None) -> dict[int, Any]:
    def forward(signum: int, _frame: object) -> None:
        with contextlib.suppress(OSError):
            if pidfd is not None:
                signal.pidfd_send_signal(pidfd, signum)  # type: ignore[attr-defined,unused-ignore]
            else:
                os.kill(pid, signum)

    previous: dict[int, Any] = {}
    for name in FORWARDED_SIGNALS:
        signum = getattr(signal, name, None)
        if signum is not None:
            previous[signum] = signal.signal(signum, forward)
    return previous


def _wait_without_daemon(pidfd: int | None, exc: Exception) -> int:
    print(
        f"pyvpn: {exc}; waiting for the command to exit (its exit status is unavailable)",
        file=sys.stderr,
    )
    if pidfd is not None:
        select.select([pidfd], [], [])
    return 1


def run(
    policy: str | int,
    command: Sequence[str],
    *,
    socket_path: str | Path = SOCKET_PATH,
    isolation: Isolation = "auto",
) -> int:
    """Run ``command`` in a policy.

    ``none``: place this process in the policy cgroup, then ``execvp``.
    ``netns``: the daemon starts the command inside the policy namespace
    and this process waits for it (``run_isolated``). ``auto`` asks the
    daemon which one the policy uses.
    """
    if not command:
        raise ValueError("a command is required")
    if isolation == "auto":
        isolation = (
            "netns" if policy_isolation(policy, socket_path=socket_path) == "netns" else "none"
        )
    if isolation == "netns":
        return run_isolated(policy, command, socket_path=socket_path)
    request_place_pid(policy, socket_path=socket_path)
    os.execvp(command[0], list(command))
    raise AssertionError("execvp returned")
