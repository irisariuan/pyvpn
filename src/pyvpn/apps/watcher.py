"""Process execution watcher with an initial procfs reconciliation scan.

The watcher accepts an event source so its matching and placement behaviour is
fully testable without opening privileged netlink sockets.
"""

from __future__ import annotations

import asyncio
import errno
import logging
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable, Iterable
from pathlib import Path
from typing import Protocol

from pyvpn.apps.cgroups import CgroupError
from pyvpn.apps.selectors import SelectorMatcher, read_process
from pyvpn.config.models import AppGroup, Policy
from pyvpn.constants import policy_cgroup

log = logging.getLogger(__name__)
Place = Callable[[int, int], Awaitable[None]]


class Subscription(Protocol):
    """An open process-event subscription (``ProcExecEvents``)."""

    def __aiter__(self) -> AsyncIterator[int]: ...

    def close(self) -> None: ...


class ProcessWatcher:
    def __init__(
        self,
        policies: Iterable[Policy],
        place_pid: Place,
        *,
        groups: Iterable[AppGroup] = (),
        proc_root: str | Path = "/proc",
    ) -> None:
        self.policies = tuple(policies)
        self.place_pid = place_pid
        self.matcher = SelectorMatcher(groups)
        self.proc_root = Path(proc_root)
        self._stopped = asyncio.Event()

    async def handle_exec(self, pid: int) -> int | None:
        """Place ``pid`` in its policy cgroup; return the matching policy id.

        Placement is decided from the process's current cgroup, not from a
        cache of PIDs, so a reused PID is always re-evaluated. A process that
        exits before it can be placed is skipped; other placement failures
        are logged and the watcher keeps running.
        """
        policy_id, _ = await self._place(pid)
        return policy_id

    async def _place(self, pid: int) -> tuple[int | None, bool]:
        """Return the matching policy id and whether ``pid`` was moved."""
        process = read_process(pid, self.proc_root)
        if process is None:
            return None, False
        policy_id = self.matcher.matching_policy(self.policies, process)
        if policy_id is None or _in_cgroup(process.cgroup, policy_cgroup(policy_id)):
            return policy_id, False
        try:
            await self.place_pid(pid, policy_id)
        except (CgroupError, OSError):
            if not (self.proc_root / str(pid)).exists():
                log.debug("process %s exited before cgroup placement", pid)
            else:
                log.exception("cannot place process %s in policy %s", pid, policy_id)
            return policy_id, False
        return policy_id, True

    async def scan(self) -> int:
        """Place already-running matching processes; return number moved."""
        try:
            pids = sorted(
                int(entry.name) for entry in self.proc_root.iterdir() if entry.name.isdecimal()
            )
        except OSError:
            return 0
        moved = 0
        for pid in pids:
            _, was_moved = await self._place(pid)
            moved += was_moved
        return moved

    async def run(self, events: AsyncIterable[int]) -> None:
        """Scan ``/proc``, then place processes from ``events``.

        ``events`` must already be subscribed when this is called, so that a
        process started during the scan is queued as an event, not missed.
        """
        await self.scan()
        async for pid in events:
            if self._stopped.is_set():
                break
            await self._place(pid)

    async def run_proc_connector(self) -> None:
        """Subscribe to Linux PROC_EVENT_EXEC events, then scan and watch."""
        from pyvpn.apps.proc_connector import ProcExecEvents

        await self.run_subscribed(ProcExecEvents.open)

    async def run_subscribed(self, subscribe: Callable[[], Awaitable[Subscription]]) -> None:
        """Watch events from ``subscribe()``, recovering from buffer overruns.

        When the kernel drops events because the socket buffer overflowed
        (``ENOBUFS``), the subscription is reopened and ``/proc`` rescanned,
        so processes whose events were lost are still placed.
        """
        while not self._stopped.is_set():
            events = await subscribe()
            try:
                await self.run(events)
                return
            except OSError as exc:
                if exc.errno != errno.ENOBUFS:
                    raise
                log.warning("process events overran the socket buffer; resubscribing")
            finally:
                events.close()

    def stop(self) -> None:
        self._stopped.set()


def _in_cgroup(cgroups: str, path: str) -> bool:
    """Whether any of the process's cgroup paths is ``path``."""
    return any(line.strip("/") == path for line in cgroups.splitlines())
