"""Start ``pyvpn run`` commands inside a policy namespace (PLAN.md §3.6).

Only root can enter a namespace the daemon owns, so the daemon starts the
command for the unprivileged caller: a small helper (``apps/nsexec.py``)
runs as root with the caller's standard descriptors, is placed in the
policy's cgroup (outside the daemon's service cgroup, so stopping the daemon
does not kill it), joins the namespace and drops to the caller's
credentials before ``exec``.

The caller's descriptors 0, 1 and 2 are copied with ``pidfd_getfd`` through
the pidfd taken when the caller connected, so they always come from that
process. Where ``pidfd_getfd`` is unavailable, ``/proc/<pid>/fd/<n>`` is
reopened (terminals, files and pipes; not sockets).
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import json
import os
import subprocess
import sys
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path

import pyvpn.apps.nsexec as nsexec_module
from pyvpn.platform.base import IsolatedCommand

SYS_PIDFD_GETFD = 438  # the same number on every architecture (asm-generic)
HELPER_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def default_helper() -> list[str]:
    return [sys.executable, "-I", str(Path(nsexec_module.__file__).resolve())]


def pidfd_getfd(pidfd: int, target_fd: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    fd = int(libc.syscall(SYS_PIDFD_GETFD, pidfd, target_fd, 0))
    if fd < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    os.set_inheritable(fd, False)
    return fd


def client_fd(pid: int, pidfd: int | None, n: int, *, proc: Path = Path("/proc")) -> int:
    """A copy of descriptor ``n`` of the caller, or ``/dev/null`` if it has none."""
    if pidfd is not None:
        with contextlib.suppress(OSError):
            return pidfd_getfd(pidfd, n)
    flags = (os.O_RDONLY if n == 0 else os.O_WRONLY) | os.O_NOCTTY | os.O_CLOEXEC
    try:
        return os.open(proc / str(pid) / "fd" / str(n), flags)
    except OSError:
        return os.open(os.devnull, flags)


def supplementary_groups(pid: int, *, proc: Path = Path("/proc")) -> tuple[int, ...]:
    for line in (proc / str(pid) / "status").read_text().splitlines():
        if line.startswith("Groups:"):
            return tuple(int(g) for g in line.split()[1:])
    return ()


class IsolatedChild:
    """A started command; ``wait`` reaps it without blocking the event loop."""

    def __init__(self, popen: subprocess.Popen[bytes]) -> None:
        self._popen = popen
        self._done: asyncio.Future[int] | None = None

    @property
    def pid(self) -> int:
        return self._popen.pid

    async def wait(self) -> int:
        if self._done is None:
            self._done = asyncio.ensure_future(self._reap())
        return await asyncio.shield(self._done)

    async def _reap(self) -> int:
        code = self._popen.poll()
        if code is not None:
            return code
        loop = asyncio.get_running_loop()
        try:
            pidfd = os.pidfd_open(self._popen.pid)  # type: ignore[attr-defined,unused-ignore]
        except (OSError, AttributeError):  # kernel < 5.3 (or not Linux)
            return await asyncio.to_thread(self._popen.wait)
        exited: asyncio.Future[None] = loop.create_future()

        def readable() -> None:
            if not exited.done():
                exited.set_result(None)

        loop.add_reader(pidfd, readable)
        try:
            await exited
        finally:
            loop.remove_reader(pidfd)
            os.close(pidfd)
        return self._popen.wait()

    def kill(self) -> None:
        with contextlib.suppress(OSError):
            self._popen.kill()


async def spawn_isolated(
    command: IsolatedCommand,
    *,
    netns: Path,
    place: Callable[[int], Awaitable[None]],
    verify_peer: Callable[[], None],
    helper: Sequence[str] | None = None,
    proc: Path = Path("/proc"),
) -> IsolatedChild:
    """Start ``command`` in ``netns``; ``place`` moves the helper's PID first."""
    if not command.argv:
        raise ValueError("a command is required")
    netns_fd = os.open(netns, os.O_RDONLY | os.O_CLOEXEC)
    try:
        st = os.fstat(netns_fd)
    finally:
        os.close(netns_fd)
    groups = supplementary_groups(command.client_pid, proc=proc) if command.uid != 0 else ()
    fds = [client_fd(command.client_pid, command.client_pidfd, n, proc=proc) for n in (0, 1, 2)]
    verify_peer()  # the descriptors and groups came from the caller, not a reused PID
    spec_r, spec_w = os.pipe()
    try:
        popen = subprocess.Popen(
            [*(helper or default_helper()), str(spec_r)],
            stdin=fds[0],
            stdout=fds[1],
            stderr=fds[2],
            pass_fds=(spec_r,),
            cwd="/",
            env={"PATH": HELPER_PATH},
            start_new_session=True,
        )
    except BaseException:
        os.close(spec_w)
        raise
    finally:
        os.close(spec_r)
        for fd in fds:
            os.close(fd)
    child = IsolatedChild(popen)
    try:
        await place(popen.pid)
        verify_peer()
        spec = {
            "netns": str(netns),
            "netns_id": [st.st_dev, st.st_ino],
            "uid": command.uid,
            "gid": command.gid,
            "groups": list(groups),
            "argv": list(command.argv),
            "env": dict(command.env),
            "cwd": command.cwd,
            "umask": command.umask,
        }
        data = json.dumps(spec).encode()
        await asyncio.to_thread(_write_all, spec_w, data)
    except BaseException:
        os.close(spec_w)  # EOF without a spec: the helper exits without exec
        spec_w = -1
        child.kill()
        with contextlib.suppress(Exception):
            await child.wait()
        raise
    finally:
        if spec_w >= 0:
            os.close(spec_w)
    return child


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]
