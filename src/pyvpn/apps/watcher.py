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
from pyvpn.apps.selectors import ProcessInfo, SelectorMatcher, pyvpn_cgroup, read_process
from pyvpn.config.models import AppGroup, Policy
from pyvpn.constants import parse_excluded_cgroup

log = logging.getLogger(__name__)
Place = Callable[[int, int], Awaitable[None]]
# Move a pid into ``pyvpn.slice/x-<hex>`` for the given policy ids.
Exclude = Callable[[int, frozenset[int]], Awaitable[None]]


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
        exclude_pid: Exclude | None = None,
        groups: Iterable[AppGroup] = (),
        proc_root: str | Path = "/proc",
    ) -> None:
        self.policies = tuple(policies)
        self.place_pid = place_pid
        self.exclude_pid = exclude_pid
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
        current = pyvpn_cgroup(process.cgroup)
        policy_id, moved, _ = await self._apply(process, current, current)
        return policy_id, moved

    async def _apply(
        self, process: ProcessInfo, inherited: str, current: str
    ) -> tuple[int | None, bool, str]:
        """Move ``process`` where it belongs.

        ``inherited`` is the pyvpn cgroup it inherits from (its own, or on a
        scan its parent's new one) and ``current`` the one it is in. Returns
        the policy id it belongs to, whether it moved, and where it is now.
        """
        target = self.matcher.target(self.policies, process, inherited)
        if target is None:
            target = inherited  # descendants follow their parent's cgroup
        decoded = parse_excluded_cgroup(target) if target else None
        policy_id = None if decoded is not None or not target else _policy_id(target)
        if not target or target == current:
            return policy_id, False, current
        pid = process.pid
        try:
            if decoded is not None:
                if self.exclude_pid is None:
                    # No way to exempt it: leave it where it is. A process in
                    # a policy cgroup stays governed by it (fail closed).
                    log.warning("cannot exclude process %s: no exclusion placement", pid)
                    return None, False, current
                await self.exclude_pid(pid, decoded.policy_ids)
            else:
                assert policy_id is not None
                await self.place_pid(pid, policy_id)
        except (CgroupError, OSError):
            if not (self.proc_root / str(pid)).exists():
                log.debug("process %s exited before cgroup placement", pid)
            else:
                log.exception("cannot place process %s in %s", pid, target)
            return policy_id, False, current
        return policy_id, True, target

    async def scan(self) -> int:
        """Place already-running matching processes; return number moved.

        Parents are handled before their children. A child still in the
        cgroup its parent was moved out of follows the parent, so an
        excluded app's existing children stay excluded with it, and an app's
        existing children join its policy.
        """
        try:
            pids = sorted(
                int(entry.name) for entry in self.proc_root.iterdir() if entry.name.isdecimal()
            )
        except OSError:
            return 0
        processes = {pid: p for pid in pids if (p := read_process(pid, self.proc_root))}
        # pid -> (cgroup before the scan, pyvpn cgroup after it)
        seen: dict[int, tuple[str, str]] = {}
        moved = 0
        for process in _parents_first(processes):
            current = pyvpn_cgroup(process.cgroup)
            inherited = current
            parent = seen.get(process.ppid) if process.ppid is not None else None
            if parent is not None and parent[0] == process.cgroup and parent[1] != current:
                inherited = parent[1]
            _, was_moved, now = await self._apply(process, inherited, current)
            seen[process.pid] = (process.cgroup, now)
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


def _policy_id(path: str) -> int:
    return int(path.rsplit("/p-", 1)[1])


def _parents_first(processes: dict[int, ProcessInfo]) -> list[ProcessInfo]:
    """``processes`` ordered so each parent comes before its children."""
    children: dict[int | None, list[int]] = {}
    for pid, process in processes.items():
        parent = process.ppid if process.ppid in processes and process.ppid != pid else None
        children.setdefault(parent, []).append(pid)
    order: list[ProcessInfo] = []
    stack = sorted(children.get(None, ()), reverse=True)
    while stack:
        pid = stack.pop()
        order.append(processes[pid])
        stack.extend(sorted(children.get(pid, ()), reverse=True))
    # A ppid cycle (a torn read of /proc) leaves pids unvisited: add them.
    visited = {p.pid for p in order}
    order.extend(processes[pid] for pid in sorted(processes) if pid not in visited)
    return order
