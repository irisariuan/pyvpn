"""Process execution watcher with an initial procfs reconciliation scan.

The watcher accepts an event source so its matching and placement behaviour is
fully testable without opening privileged netlink sockets.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from pathlib import Path

from pyvpn.apps.selectors import SelectorMatcher, read_process
from pyvpn.config.models import AppGroup, Policy

log = logging.getLogger(__name__)
Place = Callable[[int, int], Awaitable[None]]


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
        self._placed: set[tuple[int, int]] = set()
        self._stopped = asyncio.Event()

    async def handle_exec(self, pid: int) -> int | None:
        process = read_process(pid, self.proc_root)
        if process is None:
            return None
        policy_id = self.matcher.matching_policy(self.policies, process)
        if policy_id is not None and (pid, policy_id) not in self._placed:
            await self.place_pid(pid, policy_id)
            self._placed.add((pid, policy_id))
        return policy_id

    async def scan(self) -> int:
        """Place already-running matching processes; return number moved."""
        moved = 0
        try:
            pids = sorted(
                int(entry.name) for entry in self.proc_root.iterdir() if entry.name.isdecimal()
            )
        except OSError:
            return 0
        for pid in pids:
            before = len(self._placed)
            await self.handle_exec(pid)
            moved += len(self._placed) - before
        return moved

    async def run(self, events: AsyncIterator[int]) -> None:
        await self.scan()
        async for pid in events:
            if self._stopped.is_set():
                break
            try:
                await self.handle_exec(pid)
            except (OSError, PermissionError):
                log.debug("process %s disappeared before cgroup placement", pid)

    async def run_proc_connector(self) -> None:
        """Run the initial scan followed by Linux PROC_EVENT_EXEC events."""
        from pyvpn.apps.proc_connector import proc_exec_events

        await self.run(proc_exec_events())

    def stop(self) -> None:
        self._stopped.set()
