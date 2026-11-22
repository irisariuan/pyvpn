"""Target health probes with hysteresis (PLAN.md §3.2).

A target with ``"probe": true`` is usable only while TCP probes sent out
through its interface succeed. The probe loop runs in the daemon next to the
netlink watcher; only an up/down flip of a target's health changes its
:class:`~pyvpn.state.TargetStatus`, so a probe that confirms the current state
never triggers a reconcile.

This module is OS-agnostic. Sending a probe out through one interface is the
platform's job: the caller passes a :data:`~pyvpn.targets.probes.Connector`
(on Linux, :func:`pyvpn.platform.linux.netlink.tcp_connect_bound`).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field

from pyvpn.config.models import Target
from pyvpn.state import TargetStatus
from pyvpn.targets.probes import Connector, probe_target
from pyvpn.targets.watcher import InterfaceSnapshot, status_for_target

log = logging.getLogger(__name__)

PROBE_RISE = 2
"""Consecutive successes that bring a target back up after it went down."""
PROBE_FALL = 2
"""Consecutive failures that take an up target down."""
PROBE_TIMEOUT = 3.0
"""Upper bound on one TCP connect; capped at the probe interval."""

Sleep = Callable[[float], Awaitable[None]]


@dataclass
class ProbeHealth:
    """Up/down state of one probed target, with hysteresis.

    A fresh state (daemon start, or the interface just appeared, changed or
    came back) is down, and the first successful probe brings it up so a
    reconnected VPN is used at once. After that, ``fall`` consecutive
    failures take it down and ``rise`` consecutive successes bring it back.
    """

    rise: int = PROBE_RISE
    fall: int = PROBE_FALL
    up: bool = False
    _fresh: bool = field(default=True, repr=False)
    _streak: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        if self.rise < 1 or self.fall < 1:
            raise ValueError("rise and fall must be at least 1")

    def record(self, ok: bool) -> bool:
        """Record one probe result; return whether ``up`` flipped."""
        if ok == self.up:
            self._streak = 0
            return False
        self._streak += 1
        needed = 1 if self._fresh else (self.rise if ok else self.fall)
        if self._streak < needed:
            return False
        self.up = ok
        self._fresh = False
        self._streak = 0
        return True

    def reset(self) -> None:
        """Forget all results; the target is down until the next success."""
        self.up = False
        self._fresh = True
        self._streak = 0


@dataclass(frozen=True)
class _ProbeResult:
    target: str
    generation: int
    ok: bool


@dataclass(frozen=True)
class _StreamEnd:
    error: BaseException | None = None


@dataclass
class _Probed:
    """Probe bookkeeping for one target."""

    health: ProbeHealth
    # Interface the probes go out through; None while link state alone makes
    # the target unusable (no probes are sent then).
    interface: str | None = None
    generation: int = 0
    wake: asyncio.Event = field(default_factory=asyncio.Event)


class ProbingTargetWatcher:
    """Reconcile targets from interface snapshots and periodic health probes.

    Implements ``pyvpn.services.TargetWatcher``. A probed target is usable
    only when its link is usable (see :func:`status_for_target`) **and** its
    :class:`ProbeHealth` is up. Fail closed: until the first probe succeeds,
    and whenever probes keep failing, the target is down, so the policy's
    ``on_down`` (fallback or block) applies.

    Probes run every ``interval`` seconds per probed target while its link is
    usable, and immediately when its interface appears or changes. The stream
    ends when ``events`` ends.
    """

    def __init__(
        self,
        targets: Iterable[Target],
        events: AsyncIterator[Iterable[InterfaceSnapshot]],
        *,
        connect: Connector,
        endpoints: Sequence[str],
        interval: float,
        timeout: float | None = None,
        rise: int = PROBE_RISE,
        fall: int = PROBE_FALL,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        if interval <= 0:
            raise ValueError("probe interval must be greater than zero")
        self._targets = tuple(targets)
        self._events = events
        self._connect = connect
        self._endpoints = tuple(endpoints)
        self._interval = interval
        self._timeout = min(PROBE_TIMEOUT, interval) if timeout is None else timeout
        self._rise = rise
        self._fall = fall
        self._sleep = sleep

    async def statuses(self) -> AsyncIterator[dict[str, TargetStatus]]:
        queue: asyncio.Queue[tuple[InterfaceSnapshot, ...] | _ProbeResult | _StreamEnd] = (
            asyncio.Queue()
        )
        probed = {
            target.name: _Probed(ProbeHealth(self._rise, self._fall))
            for target in self._targets
            if target.probe
        }

        async def pump() -> None:
            try:
                async for snapshots in self._events:
                    queue.put_nowait(tuple(snapshots))
            except Exception as exc:
                queue.put_nowait(_StreamEnd(exc))
            else:
                queue.put_nowait(_StreamEnd())

        tasks = [asyncio.create_task(pump(), name="targets:snapshots")]
        tasks += [
            asyncio.create_task(self._probe_loop(name, state, queue), name=f"targets:probe:{name}")
            for name, state in probed.items()
        ]
        snapshots: tuple[InterfaceSnapshot, ...] | None = None
        last: dict[str, TargetStatus] | None = None
        try:
            while True:
                item = await queue.get()
                if isinstance(item, _StreamEnd):
                    if item.error is not None:
                        raise item.error
                    return
                if isinstance(item, _ProbeResult):
                    self._record(probed[item.target], item)
                else:
                    snapshots = item
                    self._track_links(probed, snapshots)
                if snapshots is None:
                    continue
                statuses = {
                    target.name: status_for_target(
                        target,
                        snapshots,
                        probe_ok=target.name in probed and probed[target.name].health.up,
                    )
                    for target in self._targets
                }
                if statuses != last:
                    last = statuses
                    yield statuses
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    def _track_links(
        self, probed: dict[str, _Probed], snapshots: tuple[InterfaceSnapshot, ...]
    ) -> None:
        """Start, retarget or stop each target's probes from link state."""
        for target in self._targets:
            state = probed.get(target.name)
            if state is None:
                continue
            link = status_for_target(target, snapshots, probe_ok=True)
            interface = link.interface if link.usable else None
            if interface == state.interface:
                continue
            # A new or vanished interface invalidates every earlier result,
            # including probes still in flight (dropped by generation).
            state.interface = interface
            state.generation += 1
            if state.health.up:
                log.warning("target %r: interface changed, probing again", target.name)
            state.health.reset()
            state.wake.set()

    def _record(self, state: _Probed, result: _ProbeResult) -> None:
        if result.generation != state.generation:
            return
        if state.health.record(result.ok):
            if state.health.up:
                log.info("target %r: probes succeed through %s; up", result.target, state.interface)
            else:
                log.warning(
                    "target %r: probes fail through %s; down", result.target, state.interface
                )

    async def _probe_loop(
        self,
        name: str,
        state: _Probed,
        queue: asyncio.Queue[tuple[InterfaceSnapshot, ...] | _ProbeResult | _StreamEnd],
    ) -> None:
        while True:
            state.wake.clear()
            interface, generation = state.interface, state.generation
            if interface is None:
                await state.wake.wait()
                continue
            try:
                ok = await probe_target(interface, self._endpoints, self._connect, self._timeout)
            except Exception:
                log.exception("target %r: probe raised; counting it as failed", name)
                ok = False
            queue.put_nowait(_ProbeResult(name, generation, ok))
            if state.wake.is_set():
                continue  # the interface changed while probing: probe again now
            await self._wait(state.wake)

    async def _wait(self, wake: asyncio.Event) -> None:
        """Sleep one interval, or less if ``wake`` is set."""
        sleeper = asyncio.ensure_future(self._sleep(self._interval))
        waker = asyncio.ensure_future(wake.wait())
        try:
            await asyncio.wait((sleeper, waker), return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (sleeper, waker):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
