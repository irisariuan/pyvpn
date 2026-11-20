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
from pyvpn.state import AppBinding, RoutingPlan
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


def peer_cred_supported() -> bool:
    import socket

    return hasattr(socket, "SO_PEERCRED")


class FailingAppManager(FakeAppManager):
    """Raises when binding the policy named ``fail_on``."""

    def __init__(self) -> None:
        super().__init__()
        self.fail_on: str | None = None

    async def bind(self, policy_id: int, policy: Any, groups: Any) -> AppBinding:
        if policy.name == self.fail_on:
            self.fail_on = None  # one-shot, so the rollback bind succeeds
            raise RuntimeError(f"cgroup for {policy.name}: simulated failure")
        return await super().bind(policy_id, policy, groups)


def with_changed_target(config: Config) -> Config:
    first, *remaining = config.policies
    changed = first.model_copy(update={"targets": ("nl",)})
    return config.model_copy(update={"policies": (changed, *remaining)})


def with_appended_app_policy(config: Config) -> Config:
    added = config.policies[0].model_copy(update={"name": "Another Japan"})
    return config.model_copy(update={"policies": (*config.policies, added)})


ROOT = PeerCred(pid=1, uid=0, gid=0)
USER = PeerCred(pid=4242, uid=1000, gid=1000)


async def test_start_binds_apps_in_one_apply(rig: Rig) -> None:
    await rig.daemon.start()
    assert len(rig.backend.plans) == 1
    apps = [p.apps for p in rig.backend.last.policies]
    assert apps[0].cgroup_paths == ("pyvpn.slice/p-1",)
    assert apps[2].any_process
    await rig.daemon.stop()
    assert rig.backend.teardowns == 0  # rules survive a normal stop
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
    assert rig.apps.unbound == [3]  # only the removed policy; 1-2 were rebound in place
    assert ("stop", 3) not in rig.dns.events  # policy 3 had no stub
    await rig.daemon.stop()


@pytest.mark.parametrize("order", [(1, 0, 2), (0, 2), (2, 0, 1)])
async def test_reload_rejects_reassigning_app_policy_slots(
    rig: Rig, order: tuple[int, ...]
) -> None:
    await rig.daemon.start()
    await rig.daemon.handle("place_pid", {"pid": 42, "policy": "Torrents"}, ROOT)
    committed = rig.config
    installed = rig.backend.installed
    rig.config = committed.model_copy(
        update={"policies": tuple(committed.policies[i] for i in order)}
    )

    with pytest.raises(ApiError, match="cgroup may still contain running apps") as error:
        await rig.daemon.handle("reload", {}, ROOT)

    assert error.value.code == "bad_request"
    assert rig.daemon.config is committed
    assert rig.backend.installed is installed
    assert rig.backend.last.policies[1].route == "unreachable"
    assert rig.apps.bound[2].name == "Torrents"
    assert rig.apps.placed == [(42, 2)] and rig.apps.unbound == []
    await rig.daemon.stop()


async def test_reload_preserves_slots_after_app_selectors_are_removed(rig: Rig) -> None:
    await rig.daemon.start()
    japan, torrents, office = rig.config.policies
    torrents = torrents.model_copy(update={"apps": (), "domains": ("torrent.example",)})
    rig.config = rig.config.model_copy(update={"policies": (japan, torrents, office)})
    await rig.daemon.handle("reload", {}, ROOT)

    rig.config = rig.config.model_copy(update={"policies": (japan, office)})
    with pytest.raises(ApiError, match="keep policy 'Torrents' at position 2"):
        await rig.daemon.handle("reload", {}, ROOT)

    assert rig.daemon.config.policies[1] == torrents
    await rig.daemon.stop()


async def test_reload_preserves_explicit_placement_in_domain_only_policy(rig: Rig) -> None:
    await rig.daemon.start()
    await rig.daemon.handle("place_pid", {"pid": 42, "policy": "Office"}, ROOT)
    rig.config = rig.config.model_copy(update={"policies": rig.config.policies[:2]})

    with pytest.raises(ApiError, match="keep policy 'Office' at position 3"):
        await rig.daemon.handle("reload", {}, ROOT)

    assert rig.apps.unbound == []
    await rig.daemon.stop()


async def test_reload_updates_in_place_and_appends_policy(rig: Rig) -> None:
    await rig.daemon.start()
    config = with_changed_target(rig.config)
    added = config.policies[-1].model_copy(
        update={"name": "Another Office", "domains": ("other.example",)}
    )
    rig.config = config.model_copy(update={"policies": (*config.policies, added)})

    await rig.daemon.handle("reload", {}, ROOT)

    assert rig.daemon.config is rig.config
    assert rig.apps.bound[1].targets == ("nl",)
    assert rig.apps.bound[2].name == "Torrents"
    assert rig.apps.bound[4] == added
    await rig.daemon.stop()


async def test_reload_rejects_duplicate_policy_names(rig: Rig) -> None:
    await rig.daemon.start()
    first, *remaining = rig.config.policies
    rig.config = rig.config.model_copy(update={"policies": (first, *remaining, first)})

    with pytest.raises(ApiError, match="policy names must be unique") as error:
        await rig.daemon.handle("reload", {}, ROOT)

    assert error.value.code == "bad_request"
    assert len(rig.daemon.config.policies) == 3
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
    for m in ("reload", "disable", "enable"):
        with pytest.raises(ApiError) as e:
            await rig.daemon.handle(m, {}, USER)
        assert e.value.code == "forbidden"
    await rig.daemon.stop()


async def test_disable_persists_across_restart(rig: Rig) -> None:
    await rig.daemon.start()
    await rig.daemon.handle("disable", {}, ROOT)
    assert rig.store.load().enabled is False
    await rig.daemon.stop()
    assert rig.backend.teardowns == 1  # not torn down twice

    plans = len(rig.backend.plans)
    rig.daemon = rig.new_daemon()
    await rig.daemon.start()
    assert len(rig.backend.plans) == plans  # stays disabled
    await rig.daemon.handle("enable", {}, ROOT)
    assert len(rig.backend.plans) == plans + 1
    assert rig.store.load().enabled
    await rig.daemon.stop()


async def test_reload_keeps_routing_disabled(rig: Rig) -> None:
    await rig.daemon.start()
    await rig.daemon.handle("disable", {}, ROOT)
    plans = len(rig.backend.plans)

    rig.config = with_changed_target(rig.config)
    await rig.daemon.handle("reload", {}, ROOT)
    assert rig.daemon.config is rig.config  # the new config is loaded
    assert not rig.daemon.reconciler.enabled and rig.store.load().enabled is False
    assert len(rig.backend.plans) == plans and rig.backend.installed is None
    assert [p.route for p in rig.daemon.status().policies] == ["not_installed"] * 3
    with pytest.raises(ApiError) as e:
        await rig.daemon.handle("place_pid", {"pid": 99, "policy": "Torrents"}, ROOT)
    assert e.value.code == "unavailable"

    # A restart while disabled stays disabled too.
    await rig.daemon.stop()
    rig.daemon = rig.new_daemon()
    await rig.daemon.start()
    assert rig.backend.installed is None

    await rig.daemon.handle("enable", {}, ROOT)
    assert rig.store.load().enabled
    assert rig.backend.installed is not None
    assert rig.backend.installed.policies[0].target is None  # "nl" is down
    assert rig.daemon.reconciler.applied == rig.daemon.reconciler.plan()
    await rig.daemon.handle("enable", {}, ROOT)  # already enabled: no-op
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
    if peer_cred_supported():
        assert resp == {"id": 7, "ok": True, "result": {"policy_id": 1}}
    else:  # no SO_PEERCRED (non-Linux): credentials missing -> rejected
        assert resp["error"]["code"] == "forbidden"

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


async def test_failed_initial_apply_keeps_placement_unavailable(rig: Rig) -> None:
    rig.backend.fail_apply = 1
    await rig.daemon.start()
    assert rig.daemon.reconciler.applied is None
    with pytest.raises(ApiError) as e:
        await rig.daemon.handle("place_pid", {"pid": 99, "policy": "Torrents"}, ROOT)
    assert e.value.code == "unavailable"
    assert rig.apps.placed == []
    await rig.daemon.reconciler.reconcile()  # what the retry timer does
    assert rig.daemon.reconciler.applied is not None
    assert await rig.daemon.handle("place_pid", {"pid": 99, "policy": "Torrents"}, ROOT) == {
        "policy_id": 2
    }
    await rig.daemon.stop()


async def test_status_reports_not_installed_until_an_apply_succeeds(rig: Rig) -> None:
    rig.backend.fail_apply = 1
    await rig.daemon.start()
    status = rig.daemon.status()
    assert status.last_error and "simulated" in status.last_error
    assert [p.route for p in status.policies] == ["not_installed"] * 3
    assert all(p.interface is None and p.target is None for p in status.policies)

    await rig.daemon.reconciler.reconcile()  # what the retry timer does
    routes = {p.name: p.route for p in rig.daemon.status().policies}
    assert routes == {"Japan": "main", "Torrents": "unreachable", "Office": "main"}

    await rig.daemon.handle("disable", {}, ROOT)
    assert [p.route for p in rig.daemon.status().policies] == ["not_installed"] * 3
    await rig.daemon.stop()


async def test_reload_apply_failure_keeps_old_config_and_bindings(rig: Rig) -> None:
    await rig.daemon.start()
    installed = rig.backend.installed
    saved = rig.store.load()
    rig.config = with_appended_app_policy(with_changed_target(rig.config))
    rig.backend.fail_apply = 1
    with pytest.raises(ApiError) as e:
        await rig.daemon.handle("reload", {}, ROOT)
    assert e.value.code == "internal"
    assert rig.backend.installed == installed
    assert rig.daemon.reconciler.applied == installed
    assert rig.store.load() == saved
    assert [p.name for p in rig.daemon.config.policies] == ["Japan", "Torrents", "Office"]
    assert {pid: p.name for pid, p in rig.apps.bound.items()} == {
        1: "Japan",
        2: "Torrents",
        3: "Office",
    }
    # Placement still resolves against the config the backend enforces.
    assert await rig.daemon.handle("place_pid", {"pid": 99, "policy": "Torrents"}, ROOT) == {
        "policy_id": 2
    }
    await rig.daemon.stop()


async def test_failed_slot_write_keeps_reload_unapplied(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    await rig.daemon.start()
    committed = rig.daemon.config
    installed = rig.backend.installed
    saved = rig.store.load()
    rig.config = with_appended_app_policy(with_changed_target(rig.config))

    def fail_save(state: PersistentState) -> None:
        assert (4, "Another Japan") in state.policy_slots
        raise OSError("state write failed")

    monkeypatch.setattr(rig.store, "save", fail_save)
    with pytest.raises(ApiError, match="previous config kept: state write failed"):
        await rig.daemon.handle("reload", {}, ROOT)

    assert rig.daemon.config is committed
    assert rig.backend.installed is installed
    assert rig.store.load() == saved
    assert rig.apps.bound == dict(enumerate(committed.policies, start=1))
    await rig.daemon.stop()


async def test_failed_slot_write_prevents_first_placement(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    await rig.daemon.start()
    params = {"pid": 42, "policy": "Office"}

    def fail_save(state: PersistentState) -> None:
        assert (3, "Office") in state.policy_slots
        raise OSError("state write failed")

    with monkeypatch.context() as patch:
        patch.setattr(rig.store, "save", fail_save)
        with pytest.raises(OSError, match="state write failed"):
            await rig.daemon.handle("place_pid", params, ROOT)
        assert rig.apps.placed == []

    await rig.daemon.handle("place_pid", params, ROOT)
    assert (3, "Office") in rig.store.load().policy_slots
    assert rig.apps.placed == [(42, 3)]
    await rig.daemon.stop()


async def test_reload_bind_failure_keeps_old_config_and_bindings(
    tmp_path: Path, config: Config
) -> None:
    rig = Rig(tmp_path, config)
    rig.apps = FailingAppManager()
    rig.daemon = rig.new_daemon()
    await rig.daemon.start()
    plans = len(rig.backend.plans)
    rig.config = with_changed_target(rig.config)
    rig.apps.fail_on = "Torrents"  # bind fails after the first policy was staged
    with pytest.raises(ApiError) as e:
        await rig.daemon.handle("reload", {}, ROOT)
    assert e.value.code == "internal"
    assert rig.apps.bound[1].targets == ("jp", "nl")
    assert len(rig.backend.plans) == plans
    assert [p.name for p in rig.daemon.config.policies] == ["Japan", "Torrents", "Office"]
    assert {pid: p.name for pid, p in rig.apps.bound.items()} == {
        1: "Japan",
        2: "Torrents",
        3: "Office",
    }
    await rig.daemon.stop()


async def test_missing_peer_credentials_are_rejected(rig: Rig) -> None:
    await rig.daemon.start()
    for method, params in [
        ("reload", {}),
        ("disable", {}),
        ("place_pid", {"pid": 99, "policy": 1}),
    ]:
        with pytest.raises(ApiError) as e:
            await rig.daemon.handle(method, params, None)
        assert e.value.code == "forbidden", method
    assert rig.apps.placed == []
    assert rig.daemon.reconciler.enabled
    await rig.daemon.handle("status", {}, None)  # read-only methods stay open
    await rig.daemon.stop()


async def test_restart_keeps_kill_switch_enforced(rig: Rig) -> None:
    await rig.daemon.start()
    installed = rig.backend.installed
    assert installed is not None and installed.policies[1].route == "unreachable"
    await rig.daemon.stop()
    assert rig.backend.teardowns == 0
    assert rig.backend.installed == installed  # still blocking between daemons
    rig.daemon = rig.new_daemon()
    await rig.daemon.start()
    assert rig.backend.teardowns == 0
    assert rig.backend.installed is not None
    await rig.daemon.stop()


async def test_teardown_on_stop_removes_rules(tmp_path: Path, config: Config) -> None:
    rig = Rig(tmp_path, config)
    rig.daemon = Daemon(
        config_loader=lambda: rig.config,
        backend=rig.backend,
        targets=rig.targets,
        apps=rig.apps,
        socket_path=rig.sock,
        teardown_on_stop=True,  # uninstall path
    )
    await rig.daemon.start()
    await rig.daemon.stop()
    assert rig.backend.teardowns == 1 and rig.backend.installed is None


async def test_place_pid_unavailable_while_disabled(rig: Rig) -> None:
    await rig.daemon.start()
    await rig.daemon.handle("disable", {}, ROOT)
    with pytest.raises(ApiError) as e:
        await rig.daemon.handle("place_pid", {"pid": 99, "policy": "Torrents"}, ROOT)
    assert e.value.code == "unavailable"
    assert rig.apps.placed == []
    await rig.daemon.handle("enable", {}, ROOT)
    assert await rig.daemon.handle("place_pid", {"pid": 99, "policy": "Torrents"}, ROOT) == {
        "policy_id": 2
    }
    await rig.daemon.stop()


async def test_policy_slots_survive_restart(rig: Rig) -> None:
    await rig.daemon.start()
    await rig.daemon.handle("place_pid", {"pid": 42, "policy": "Office"}, ROOT)
    assert (3, "Office") in rig.store.load().policy_slots
    await rig.daemon.stop()  # rules and cgroups stay in force

    committed = rig.config
    rig.config = committed.model_copy(update={"policies": tuple(reversed(committed.policies))})
    rig.daemon = rig.new_daemon()
    with pytest.raises(ApiError, match="keep policy 'Japan' at position 1"):
        await rig.daemon.start()

    rig.config = committed
    rig.daemon = rig.new_daemon()
    await rig.daemon.start()
    await rig.daemon.stop()


def test_unreadable_policy_slots_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"enabled": True, "policy_slots": [[1, "a"], ["x", 2], 3]}))
    assert StateStore(path).load() == PersistentState(enabled=True, policy_slots=((1, "a"),))


async def test_second_daemon_does_not_take_over_the_socket(rig: Rig) -> None:
    await rig.daemon.start()
    installed = rig.backend.installed
    saved = rig.store.load()
    rig.config = with_appended_app_policy(rig.config)
    second = rig.new_daemon()
    with pytest.raises(RuntimeError, match="another pyvpn daemon"):
        await second.start()
    await second.stop()
    assert rig.backend.installed is installed
    assert rig.store.load() == saved
    assert 4 not in rig.apps.bound
    assert (await rig.call("status"))["ok"]  # the first daemon still serves
    await rig.daemon.stop()
    assert not rig.sock.exists()


async def test_instance_lock_covers_startup_before_the_api_serves(rig: Rig) -> None:
    started = asyncio.Event()
    resume = asyncio.Event()
    apply = rig.backend.apply

    async def pause_apply(plan: RoutingPlan) -> None:
        started.set()
        await resume.wait()
        await apply(plan)

    rig.backend.apply = pause_apply  # type: ignore[method-assign]
    first = asyncio.create_task(rig.daemon.start())
    try:
        await started.wait()
        assert rig.backend.installed is None
        with pytest.raises(RuntimeError, match="another pyvpn daemon"):
            await rig.new_daemon().start()
    finally:
        resume.set()
        await first
        await rig.daemon.stop()


async def test_close_leaves_a_successors_socket(rig: Rig) -> None:
    await rig.daemon.start()
    rig.sock.unlink()  # e.g. removed by hand; a new daemon binds the path
    successor = rig.new_daemon()
    await successor.server.start()
    await rig.daemon.stop()
    assert rig.sock.exists()
    await successor.server.close()


async def test_stop_closes_an_open_api_connection(rig: Rig) -> None:
    await rig.daemon.start()
    reader, writer = await asyncio.open_unix_connection(str(rig.sock))
    try:
        writer.write(b'{"method":"status"}\n')
        await writer.drain()
        assert json.loads(await reader.readline())["ok"]

        await rig.daemon.stop()

        assert await reader.read() == b""
    finally:
        writer.close()
        await writer.wait_closed()


async def test_stop_completes_when_teardown_fails(tmp_path: Path, config: Config) -> None:
    rig = Rig(tmp_path, config)
    daemon = Daemon(
        config_loader=lambda: rig.config,
        backend=rig.backend,
        targets=rig.targets,
        apps=rig.apps,
        dns=rig.dns,
        store=rig.store,
        socket_path=rig.sock,
        teardown_on_stop=True,
    )
    await daemon.start()

    async def broken() -> None:
        raise RuntimeError("teardown failed")

    daemon.reconciler.disable = broken  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="teardown failed"):
        await daemon.stop()
    await asyncio.wait_for(daemon.wait_stopped(), 1)
