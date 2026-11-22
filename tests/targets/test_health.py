"""Target health probes (PLAN.md §3.2). Fakes only: no real sockets."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import threading
from collections.abc import AsyncIterator, Callable, Coroutine
from typing import Any

import pytest

from pyvpn.config.models import Settings, Target
from pyvpn.platform.linux.netlink import NetlinkTargetWatcher
from pyvpn.services import TargetWatcher
from pyvpn.state import TargetStatus
from pyvpn.targets import InterfaceSnapshot, ProbeHealth, ProbingTargetWatcher

ENDPOINTS = ("192.0.2.1:443",)


def _snap(name: str = "wg0", up: bool = True, ifindex: int = 42) -> InterfaceSnapshot:
    return InterfaceSnapshot(name, ifindex, up, (ipaddress.ip_address("10.0.0.2"),))


# -- hysteresis --------------------------------------------------------------


def test_fresh_health_is_down_and_one_success_brings_it_up() -> None:
    health = ProbeHealth(rise=3, fall=3)
    assert not health.up
    assert not health.record(False)
    assert not health.up
    assert health.record(True)
    assert health.up


def test_up_needs_fall_consecutive_failures_to_go_down() -> None:
    health = ProbeHealth(rise=2, fall=2)
    health.record(True)
    assert not health.record(False)
    assert health.up
    assert not health.record(True)  # a success breaks the failure streak
    assert not health.record(False)
    assert health.record(False)
    assert not health.up


def test_down_needs_rise_consecutive_successes_to_come_back() -> None:
    health = ProbeHealth(rise=2, fall=1)
    health.record(True)
    health.record(False)
    assert not health.up
    assert not health.record(True)
    assert not health.record(False)  # streak broken
    assert not health.record(True)
    assert health.record(True)
    assert health.up


def test_reset_makes_health_fresh_and_down() -> None:
    health = ProbeHealth(rise=5, fall=5)
    health.record(True)
    health.reset()
    assert not health.up
    assert health.record(True)  # fresh again: one success is enough


def test_rise_and_fall_must_be_positive() -> None:
    with pytest.raises(ValueError):
        ProbeHealth(rise=0)
    with pytest.raises(ValueError):
        ProbeHealth(fall=0)


# -- the probing watcher -----------------------------------------------------


class Ticks:
    """Fake ``sleep``: each ``tick()`` ends one pending probe interval."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[None] = asyncio.Queue()
        self.intervals: list[float] = []

    async def sleep(self, interval: float) -> None:
        self.intervals.append(interval)
        await self._queue.get()

    def tick(self) -> None:
        self._queue.put_nowait(None)


class Connector:
    """Fake bound-socket connector with a switchable result."""

    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.calls: list[tuple[str, str, int, float]] = []
        self.lock = threading.Lock()

    def __call__(self, interface: str, host: str, port: int, timeout: float) -> bool:
        with self.lock:
            self.calls.append((interface, host, port, timeout))
            return self.ok


class Snapshots:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[tuple[InterfaceSnapshot, ...] | BaseException | None] = (
            asyncio.Queue()
        )

    def push(self, *snapshots: InterfaceSnapshot) -> None:
        self._queue.put_nowait(snapshots)

    def fail(self, error: BaseException) -> None:
        self._queue.put_nowait(error)

    def end(self) -> None:
        self._queue.put_nowait(None)

    async def events(self) -> AsyncIterator[tuple[InterfaceSnapshot, ...]]:
        while True:
            item = await self._queue.get()
            if item is None:
                return
            if isinstance(item, BaseException):
                raise item
            yield item


class Run:
    """Consume a watcher in a task so tests can inspect what it yielded."""

    def __init__(self, watcher: TargetWatcher) -> None:
        self.seen: list[dict[str, TargetStatus]] = []
        self.task = asyncio.create_task(self._consume(watcher))

    async def _consume(self, watcher: TargetWatcher) -> None:
        async for statuses in watcher.statuses():
            self.seen.append(statuses)

    def usable(self, name: str = "vpn") -> list[bool]:
        return [statuses[name].usable for statuses in self.seen]

    async def stop(self) -> None:
        self.task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self.task


async def until(condition: Callable[[], bool], timeout: float = 2.0) -> None:
    async def wait() -> None:
        while not condition():
            await asyncio.sleep(0.002)

    await asyncio.wait_for(wait(), timeout)


async def settle() -> None:
    """Let queued probe results reach the watcher."""
    for _ in range(20):
        await asyncio.sleep(0)
    await asyncio.sleep(0.01)


def _watcher(
    targets: tuple[Target, ...],
    snapshots: Snapshots,
    connect: Any,
    ticks: Ticks,
    **kw: Any,
) -> ProbingTargetWatcher:
    return ProbingTargetWatcher(
        targets,
        snapshots.events(),
        connect=connect,
        endpoints=ENDPOINTS,
        interval=15.0,
        sleep=ticks.sleep,
        **kw,
    )


def _async(test: Callable[[], Coroutine[Any, Any, None]]) -> Callable[[], None]:
    def run() -> None:
        asyncio.run(test())

    run.__name__ = test.__name__
    return run


@_async
async def test_probed_target_follows_probes_with_hysteresis() -> None:
    target = Target(name="vpn", interface="wg0", probe=True)
    snapshots, connect, ticks = Snapshots(), Connector(ok=True), Ticks()
    run = Run(_watcher((target,), snapshots, connect, ticks, rise=2, fall=2))
    snapshots.push(_snap())

    await until(lambda: run.usable() == [False, True])  # first probe: up at once
    assert connect.calls == [("wg0", "192.0.2.1", 443, 3.0)]

    connect.ok = False
    ticks.tick()
    await until(lambda: len(connect.calls) == 2)
    await settle()
    assert run.usable() == [False, True]  # one failure is not enough

    ticks.tick()
    await until(lambda: run.usable() == [False, True, False])

    connect.ok = True
    ticks.tick()
    await until(lambda: len(connect.calls) == 4)
    await settle()
    assert run.usable() == [False, True, False]  # one success is not enough

    ticks.tick()
    await until(lambda: run.usable() == [False, True, False, True])
    assert ticks.intervals and set(ticks.intervals) == {15.0}
    await run.stop()


@_async
async def test_a_failing_probe_never_brings_a_target_up() -> None:
    target = Target(name="vpn", interface="wg0", probe=True)
    snapshots, connect, ticks = Snapshots(), Connector(ok=False), Ticks()
    run = Run(_watcher((target,), snapshots, connect, ticks))
    snapshots.push(_snap())
    for calls in (1, 2, 3):
        await until(lambda calls=calls: len(connect.calls) == calls)  # type: ignore[misc]
        ticks.tick()
    await settle()
    assert run.usable() == [False]
    await run.stop()


@_async
async def test_no_probes_while_the_link_is_down_and_link_loss_drops_at_once() -> None:
    target = Target(name="vpn", interface="wg0", probe=True)
    snapshots, connect, ticks = Snapshots(), Connector(ok=True), Ticks()
    run = Run(_watcher((target,), snapshots, connect, ticks))

    snapshots.push(_snap(up=False))
    await until(lambda: run.usable() == [False])
    await settle()
    assert connect.calls == []

    snapshots.push(_snap())  # link comes up: probe right away, no tick needed
    await until(lambda: run.usable()[-1:] == [True])

    snapshots.push()  # interface gone: down without waiting for probes
    await until(lambda: run.usable()[-1:] == [False])
    assert run.seen[-1]["vpn"].interface is None

    snapshots.push(_snap())  # back: health starts fresh, one success suffices
    await until(lambda: run.usable()[-1:] == [True])
    assert len(connect.calls) == 2
    await run.stop()


@_async
async def test_a_new_interface_resets_health_and_is_probed_at_once() -> None:
    target = Target(name="vpn", interface="tun*", probe=True)
    snapshots, connect, ticks = Snapshots(), Connector(ok=True), Ticks()
    run = Run(_watcher((target,), snapshots, connect, ticks))
    snapshots.push(_snap("tun0", ifindex=1))
    await until(lambda: run.usable() == [False, True])

    snapshots.push(_snap("tun1", ifindex=2))
    await until(lambda: [c[0] for c in connect.calls] == ["tun0", "tun1"])
    await until(lambda: run.seen[-1]["vpn"].interface == "tun1" and run.usable()[-1])
    # tun1 was down (unprobed) before its first probe succeeded.
    assert [s["vpn"].interface for s in run.seen] == ["tun0", "tun0", "tun1", "tun1"]
    assert run.usable() == [False, True, False, True]
    await run.stop()


@_async
async def test_a_result_from_an_old_interface_is_ignored() -> None:
    target = Target(name="vpn", interface="wg0", probe=True)
    snapshots, ticks = Snapshots(), Ticks()
    release = threading.Event()
    entered = threading.Event()

    def slow(interface: str, host: str, port: int, timeout: float) -> bool:
        entered.set()
        release.wait(5)
        return True

    run = Run(_watcher((target,), snapshots, slow, ticks))
    try:
        snapshots.push(_snap())
        await until(entered.is_set)
        snapshots.push(_snap(up=False))  # link lost while the probe is in flight
        await until(lambda: len(run.seen) >= 1)
    finally:
        release.set()
    await settle()
    assert run.usable() == [False]  # the late success must not bring it up
    await run.stop()


@_async
async def test_a_recreated_interface_with_the_same_name_starts_fresh() -> None:
    target = Target(name="vpn", interface="wg0", probe=True)
    snapshots, connect, ticks = Snapshots(), Connector(ok=True), Ticks()
    run = Run(_watcher((target,), snapshots, connect, ticks))
    snapshots.push(_snap(ifindex=42))
    await until(lambda: run.usable() == [False, True])

    # Delete + re-create coalesced into one burst: same name, new index.
    connect.ok = False
    snapshots.push(_snap(ifindex=43))
    await until(lambda: len(connect.calls) == 2)  # probed at once, no tick
    await settle()
    assert [(s["vpn"].ifindex, s["vpn"].usable) for s in run.seen] == [
        (42, False),
        (42, True),
        (43, False),  # down before its own probe, not carried over from 42
    ]
    await run.stop()


@_async
async def test_a_result_from_a_replaced_ifindex_is_ignored() -> None:
    target = Target(name="vpn", interface="wg0", probe=True)
    snapshots, ticks = Snapshots(), Ticks()
    release = threading.Event()
    entered = threading.Event()
    results = iter((True, False))

    def slow(interface: str, host: str, port: int, timeout: float) -> bool:
        ok = next(results, False)
        if ok:  # the first probe, for ifindex 42, is still in flight
            entered.set()
            release.wait(5)
        return ok

    run = Run(_watcher((target,), snapshots, slow, ticks))
    try:
        snapshots.push(_snap(ifindex=42))
        await until(entered.is_set)
        snapshots.push(_snap(ifindex=43))  # replaced while that probe runs
        await until(lambda: len(run.seen) >= 2)
    finally:
        release.set()
    await settle()
    # The late success belongs to ifindex 42 and must not bring 43 up.
    assert [(s["vpn"].ifindex, s["vpn"].usable) for s in run.seen] == [(42, False), (43, False)]
    await run.stop()


@_async
async def test_a_raising_connector_counts_as_a_failure() -> None:
    target = Target(name="vpn", interface="wg0", probe=True)
    snapshots, ticks = Snapshots(), Ticks()
    calls: list[str] = []

    def broken(interface: str, host: str, port: int, timeout: float) -> bool:
        calls.append(interface)
        raise OSError("boom")

    run = Run(_watcher((target,), snapshots, broken, ticks))
    snapshots.push(_snap())
    await until(lambda: len(calls) == 1)
    ticks.tick()
    await until(lambda: len(calls) == 2)  # the loop keeps running
    await settle()
    assert run.usable() == [False]
    await run.stop()


@_async
async def test_unprobed_targets_follow_link_state_and_send_no_probes() -> None:
    plain = Target(name="office", interface="eth0")
    snapshots, connect, ticks = Snapshots(), Connector(), Ticks()
    run = Run(_watcher((plain,), snapshots, connect, ticks))
    snapshots.push(_snap("eth0"))
    await until(lambda: run.usable("office") == [True])
    snapshots.push(_snap("eth0", up=False))
    await until(lambda: run.usable("office") == [True, False])
    assert connect.calls == []
    await run.stop()


@_async
async def test_stream_end_stops_the_probes() -> None:
    target = Target(name="vpn", interface="wg0", probe=True)
    snapshots, connect, ticks = Snapshots(), Connector(), Ticks()
    watcher = _watcher((target,), snapshots, connect, ticks)
    snapshots.push(_snap())
    snapshots.end()
    seen = await asyncio.wait_for(_drain(watcher), 2)
    assert seen and not seen[0]["vpn"].usable
    assert [t for t in asyncio.all_tasks() if t.get_name().startswith("targets:")] == []


@_async
async def test_a_failing_snapshot_stream_raises() -> None:
    target = Target(name="vpn", interface="wg0", probe=True)
    snapshots, connect, ticks = Snapshots(), Connector(), Ticks()
    snapshots.fail(RuntimeError("netlink died"))
    with pytest.raises(RuntimeError, match="netlink died"):
        await asyncio.wait_for(_drain(_watcher((target,), snapshots, connect, ticks)), 2)


async def _drain(watcher: TargetWatcher) -> list[dict[str, TargetStatus]]:
    return [statuses async for statuses in watcher.statuses()]


def test_timeout_is_capped_at_the_interval_and_interval_must_be_positive() -> None:
    async def nothing() -> AsyncIterator[tuple[InterfaceSnapshot, ...]]:
        return
        yield

    with pytest.raises(ValueError):
        ProbingTargetWatcher((), nothing(), connect=Connector(), endpoints=ENDPOINTS, interval=0)
    watcher = ProbingTargetWatcher(
        (), nothing(), connect=Connector(), endpoints=ENDPOINTS, interval=0.5
    )
    assert watcher._timeout == 0.5


@_async
async def test_netlink_watcher_probes_with_the_configured_settings() -> None:
    target = Target(name="vpn", interface="wg0", probe=True)
    snapshots, connect = Snapshots(), Connector()

    class Reader:
        def events(self) -> AsyncIterator[tuple[InterfaceSnapshot, ...]]:
            return snapshots.events()

    settings = Settings(probe_targets=("[2001:db8::1]:853",), probe_interval=60)
    watcher: TargetWatcher = NetlinkTargetWatcher(
        (target,), Reader(), settings=settings, connect=connect
    )
    run = Run(watcher)
    snapshots.push(_snap())
    await until(lambda: run.usable() == [False, True])
    assert connect.calls == [("wg0", "2001:db8::1", 853, 3.0)]
    await run.stop()
