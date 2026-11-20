from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import pytest

from pyvpn.config.models import Config
from pyvpn.daemon.core import Daemon
from pyvpn.daemon.persistence import PersistentState, StateStore
from pyvpn.daemon.server import ApiError, PeerCred
from tests.daemon.conftest import make_config
from tests.fakes import FakeAppManager, FakeBackend, FakeDnsService, FakeTargetWatcher
from tests.fakes.targets import up


class Rig:
    def __init__(self, tmp: Path, config: Config) -> None:
        self.config = config
        self.backend = FakeBackend()
        self.targets = FakeTargetWatcher()
        self.apps = FakeAppManager()
        self.dns = FakeDnsService()
        self.store = StateStore(tmp / "state.json")
        self.sock = tmp / "pyvpn.sock"
        self.daemon = self.new_daemon()

    def new_daemon(self) -> Daemon:
        return Daemon(
            config_loader=lambda: self.config,
            backend=self.backend,
            targets=self.targets,
            apps=self.apps,
            dns=self.dns,
            store=self.store,
            socket_path=self.sock,
        )

    async def settle(self) -> None:
        for _ in range(5):
            await asyncio.sleep(0)

    async def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        reader, writer = await asyncio.open_unix_connection(str(self.sock))
        writer.write(
            json.dumps({"id": 7, "method": method, "params": params or {}}).encode() + b"\n"
        )
        await writer.drain()
        resp: dict[str, Any] = json.loads(await reader.readline())
        writer.close()
        await writer.wait_closed()
        return resp


@pytest.fixture
def rig(tmp_path: Path, config: Config) -> Rig:
    return Rig(tmp_path, config)


ROOT = PeerCred(pid=1, uid=0, gid=0)
USER = PeerCred(pid=4242, uid=1000, gid=1000)


async def test_start_binds_apps_in_one_apply(rig: Rig) -> None:
    await rig.daemon.start()
    assert len(rig.backend.plans) == 1
    apps = [p.apps for p in rig.backend.last.policies]
    assert apps[0].cgroup_paths == ("pyvpn.slice/p-1",)
    assert apps[2].any_process
    await rig.daemon.stop()
    assert rig.backend.teardowns == 1
    assert not rig.sock.exists()


async def test_target_events_drive_plans(rig: Rig) -> None:
    await rig.daemon.start()
    rig.targets.push(up("jp", "wg-jp"), up("nl", "tun0"))
    await rig.settle()
    assert [p.interface for p in rig.backend.last.policies] == ["wg-jp", "tun0", None]
    await rig.daemon.stop()


async def test_watcher_death_fails_closed(rig: Rig) -> None:
    await rig.daemon.start()
    rig.targets.push(up("nl", "tun0"))
    await rig.settle()
    assert rig.backend.last.policies[1].route == "dev"
    rig.targets.stream.fail(RuntimeError("netlink socket closed"))
    await rig.settle()
    assert rig.backend.last.policies[1].route == "unreachable"
    assert "target watcher failed" in (rig.daemon.reconciler.last_error or "")
    await rig.daemon.stop()


async def test_reload_has_no_unbound_window(rig: Rig) -> None:
    await rig.daemon.start()
    before = len(rig.backend.plans)
    rig.config = make_config(policies=[*rig.config.model_dump()["policies"][:2]])
    await rig.daemon.handle("reload", {}, ROOT)
    new_plans = rig.backend.plans[before:]
    assert len(new_plans) == 1
    assert len(new_plans[0].policies) == 2
    assert all(p.apps.cgroup_paths for p in new_plans[0].policies)
    assert rig.apps.unbound == [1, 2, 3]
    assert ("stop", 3) not in rig.dns.events  # policy 3 had no stub
    await rig.daemon.stop()


async def test_reload_with_bad_config_keeps_old(rig: Rig) -> None:
    await rig.daemon.start()

    def broken() -> Config:
        raise ValueError("unknown target 'xx'")

    rig.daemon._load = broken
    with pytest.raises(ApiError) as e:
        await rig.daemon.handle("reload", {}, ROOT)
    assert e.value.code == "bad_request"
    assert len(rig.daemon.config.policies) == 3
    await rig.daemon.stop()


async def test_place_pid_rules(rig: Rig) -> None:
    await rig.daemon.start()
    assert await rig.daemon.handle("place_pid", {"pid": 4242, "policy": "Torrents"}, USER) == {
        "policy_id": 2
    }
    assert await rig.daemon.handle("place_pid", {"pid": 99, "policy": 1}, ROOT) == {"policy_id": 1}
    assert rig.apps.placed == [(4242, 2), (99, 1)]
    for params, peer, code in [
        ({"pid": 99, "policy": 1}, USER, "forbidden"),
        ({"pid": 4242, "policy": "nope"}, USER, "not_found"),
        ({"pid": 4242, "policy": 9}, USER, "not_found"),
        ({"pid": 4242, "policy": True}, USER, "not_found"),
        ({"pid": -1, "policy": 1}, ROOT, "bad_request"),
        ({"policy": 1}, ROOT, "bad_request"),
    ]:
        with pytest.raises(ApiError) as e:
            await rig.daemon.handle("place_pid", params, peer)
        assert e.value.code == code, params
    await rig.daemon.stop()


async def test_admin_methods_need_root(rig: Rig) -> None:
    await rig.daemon.start()
    if os.geteuid() == USER.uid:
        pytest.skip("test user uid collides with daemon uid")
    for m in ("reload", "disable"):
        with pytest.raises(ApiError) as e:
            await rig.daemon.handle(m, {}, USER)
        assert e.value.code == "forbidden"
    await rig.daemon.stop()


async def test_disable_persists_across_restart(rig: Rig) -> None:
    await rig.daemon.start()
    await rig.daemon.handle("disable", {}, ROOT)
    assert rig.store.load() == PersistentState(enabled=False)
    await rig.daemon.stop()
    assert rig.backend.teardowns == 1  # not torn down twice

    plans = len(rig.backend.plans)
    rig.daemon = rig.new_daemon()
    await rig.daemon.start()
    assert len(rig.backend.plans) == plans  # stays disabled
    await rig.daemon.handle("reload", {}, ROOT)  # reload re-enables
    assert len(rig.backend.plans) == plans + 1
    assert rig.store.load().enabled
    await rig.daemon.stop()


async def test_socket_protocol(rig: Rig) -> None:
    await rig.daemon.start()
    rig.targets.push(up("nl", "tun0"))
    await rig.settle()

    resp = await rig.call("status")
    assert resp["ok"] and resp["id"] == 7
    pols = {p["name"]: p for p in resp["result"]["policies"]}
    assert pols["Torrents"]["route"] == "dev" and pols["Torrents"]["interface"] == "tun0"
    assert resp["result"]["targets"]["nl"] == {"interface": "tun0", "usable": True}

    resp = await rig.call("apps")
    assert resp["result"][0]["cgroup_paths"] == ["pyvpn.slice/p-1"]

    resp = await rig.call("place_pid", {"pid": os.getpid(), "policy": "Japan"})
    assert resp == {"id": 7, "ok": True, "result": {"policy_id": 1}}

    assert (await rig.call("frobnicate"))["error"]["code"] == "unknown_method"
    assert (await rig.call("audit"))["error"]["code"] == "unavailable"

    reader, writer = await asyncio.open_unix_connection(str(rig.sock))
    writer.write(b"not json\n[1]\n")
    await writer.drain()
    assert json.loads(await reader.readline())["error"]["code"] == "bad_request"
    assert json.loads(await reader.readline())["error"]["code"] == "bad_request"
    writer.close()
    await writer.wait_closed()
    await rig.daemon.stop()
