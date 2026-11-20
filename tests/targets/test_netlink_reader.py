from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from pyvpn.platform.linux.netlink import NetlinkReader


def test_sync_pyroute_client_runs_off_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    loop_thread = threading.get_ident()
    constructor_threads: list[int] = []

    class FakeIPRoute:
        def __init__(self) -> None:
            constructor_threads.append(threading.get_ident())
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                pass
            else:
                raise AssertionError("synchronous IPRoute was constructed in the event loop")
            self.sockets = socket.socketpair()
            self.socket = self.sockets[0]

        def __enter__(self) -> FakeIPRoute:
            return self

        def __exit__(self, *_: object) -> None:
            self.sockets[0].close()
            self.sockets[1].close()

        def bind(self, *, groups: int) -> None:
            assert groups

        def get_links(self) -> list[dict[str, Any]]:
            return []

        def get_addr(self) -> list[dict[str, Any]]:
            return []

        def get_routes(self) -> list[dict[str, Any]]:
            return []

    pyroute2 = ModuleType("pyroute2")
    pyroute2.__dict__.update({"IPRoute": FakeIPRoute, "__path__": []})
    netlink = ModuleType("pyroute2.netlink")
    netlink.__dict__["__path__"] = []
    rtnl = ModuleType("pyroute2.netlink.rtnl")
    for group, value in (
        ("RTMGRP_LINK", 1),
        ("RTMGRP_IPV4_IFADDR", 2),
        ("RTMGRP_IPV6_IFADDR", 4),
        ("RTMGRP_IPV4_ROUTE", 8),
        ("RTMGRP_IPV6_ROUTE", 16),
    ):
        setattr(rtnl, group, value)
    monkeypatch.setitem(sys.modules, "pyroute2", pyroute2)
    monkeypatch.setitem(sys.modules, "pyroute2.netlink", netlink)
    monkeypatch.setitem(sys.modules, "pyroute2.netlink.rtnl", rtnl)

    async def read_initial_snapshot() -> tuple[object, ...]:
        events = NetlinkReader().events()
        try:
            return await asyncio.wait_for(anext(events), timeout=5)
        finally:
            await events.aclose()

    assert asyncio.run(read_initial_snapshot()) == ()
    assert len(constructor_threads) == 2  # event socket + separate dump socket
    assert loop_thread not in constructor_threads


def test_dumps_never_run_on_the_event_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """A change during a dump must not be swallowed by the multicast socket."""
    instances: list[Any] = []

    class FakeIPRoute:
        def __init__(self) -> None:
            self.bound = False
            self.dumped = 0
            self.sockets = socket.socketpair()
            self.socket = self.sockets[0]
            instances.append(self)

        def __enter__(self) -> FakeIPRoute:
            return self

        def __exit__(self, *_: object) -> None:
            self.sockets[0].close()
            self.sockets[1].close()

        def bind(self, *, groups: int) -> None:
            self.bound = True

        def get(self) -> list[dict[str, Any]]:
            self.sockets[0].recv(64)
            return [{"event": "RTM_NEWLINK"}]

        def get_links(self) -> list[dict[str, Any]]:
            assert not self.bound, "dump ran on the multicast-bound socket"
            self.dumped += 1
            return []

        def get_addr(self) -> list[dict[str, Any]]:
            return []

        def get_routes(self) -> list[dict[str, Any]]:
            return []

    reader = NetlinkReader()
    stopping = threading.Event()
    published: list[object] = []

    def publish(snapshots: object) -> None:
        published.append(snapshots)
        if len(published) == 1:
            events = next(i for i in instances if i.bound)
            events.sockets[1].send(b"x")  # an event arrives after the first dump
        else:
            stopping.set()

    reader._watch(FakeIPRoute, 1, stopping, publish)
    events = next(i for i in instances if i.bound)
    dumps = next(i for i in instances if not i.bound)
    assert len(published) == 2
    assert dumps.dumped == 2 and events.dumped == 0


@pytest.mark.integration
def test_live_reader_receives_link_change_in_private_network_namespace() -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("requires Linux network namespaces")
    unshare = shutil.which("unshare")
    if unshare is None or shutil.which("ip") is None:
        pytest.skip("requires unshare and iproute2")

    permission_check = subprocess.run(
        [unshare, "--net", sys.executable, "-c", "pass"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if permission_check.returncode:
        pytest.skip(f"network namespace creation unavailable: {permission_check.stderr.strip()}")

    script = """
import asyncio
import subprocess
from pyvpn.platform.linux.netlink import NetlinkReader

async def main():
    subprocess.run(["ip", "link", "set", "lo", "down"], check=True, capture_output=True)
    events = NetlinkReader().events()
    try:
        initial = await asyncio.wait_for(anext(events), timeout=5)
        assert any(item.name == "lo" and not item.up for item in initial), initial
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True, capture_output=True)
        updated = await asyncio.wait_for(anext(events), timeout=5)
        assert any(item.name == "lo" and item.up for item in updated), updated
    finally:
        await events.aclose()

asyncio.run(main())
"""
    root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join(
        item for item in (str(root / "src"), existing_pythonpath) if item
    )
    result = subprocess.run(
        [unshare, "--net", sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
