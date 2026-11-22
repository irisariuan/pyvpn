"""``isolation: netns`` in the daemon: config checks, run_isolated, wait_isolated."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from pyvpn.config.models import Config
from pyvpn.daemon.core import Daemon
from pyvpn.daemon.persistence import StateStore
from pyvpn.daemon.server import ApiError, PeerCred
from pyvpn.platform.base import IsolatedCommand
from tests.daemon.conftest import make_config
from tests.fakes import (
    FakeAppManager,
    FakeBackend,
    FakeDnsService,
    FakeRuleMatcher,
    FakeTargetWatcher,
)
from tests.fakes.targets import up

_ALIVE_R, _ALIVE_W = os.pipe()
USER = PeerCred(pid=4242, uid=1000, gid=1000, pidfd=_ALIVE_R)
OTHER = PeerCred(pid=4343, uid=1001, gid=1001, pidfd=_ALIVE_R)
ROOT = PeerCred(pid=1, uid=0, gid=0, pidfd=_ALIVE_R)
RUN = {"policy": "Torrents", "argv": ["qbittorrent"], "env": {"HOME": "/home/u"}, "cwd": "/home/u"}


def isolated_config(**leak: Any) -> Config:
    config = make_config()
    torrents = config.policies[1].model_copy(update={"isolation": "netns"})
    if leak:
        torrents = torrents.model_copy(update={"leak": torrents.leak.model_copy(update=leak)})
    return config.model_copy(
        update={"policies": (config.policies[0], torrents, *config.policies[2:])}
    )


class FakeChild:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.exit: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def wait(self) -> int:
        return await asyncio.shield(self.exit)


class FakeLauncher:
    def __init__(self) -> None:
        self.commands: list[IsolatedCommand] = []
        self.children: list[FakeChild] = []
        self.fail: Exception | None = None

    async def __call__(
        self, command: IsolatedCommand, verify_peer: Callable[[], None]
    ) -> FakeChild:
        verify_peer()
        if self.fail is not None:
            raise self.fail
        self.commands.append(command)
        child = FakeChild(5000 + len(self.children))
        self.children.append(child)
        return child


def daemon(
    tmp: Path, config: Config, *, netns: bool = True, launcher: FakeLauncher | None = None
) -> tuple[Daemon, FakeBackend, FakeTargetWatcher]:
    backend = FakeBackend(netns=netns)
    targets = FakeTargetWatcher()
    d = Daemon(
        config_loader=lambda: config,
        backend=backend,
        targets=targets,
        apps=FakeAppManager(),
        dns=FakeDnsService(),
        matcher_factory=lambda config: FakeRuleMatcher(),
        spawn_isolated=launcher,
        store=StateStore(tmp / "state.json"),
        socket_path=tmp / "pyvpn.sock",
    )
    return d, backend, targets


async def test_isolation_is_refused_without_backend_support(tmp_path: Path) -> None:
    d, backend, _ = daemon(tmp_path, isolated_config(), netns=False, launcher=FakeLauncher())
    with pytest.raises(ApiError, match="not supported by this backend"):
        await d.start()
    assert backend.plans == []
    d2, _, _ = daemon(tmp_path, isolated_config(), netns=True, launcher=None)
    with pytest.raises(ApiError, match="not supported by this backend"):
        await d2.start()


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"domains": ("example.com",), "leak": {"dns_via_target": True}}, "only drop: rules"),
        ({"domains": ("drop:ads.example", "cidr:10.0.0.0/8"), "leak": {}}, "only drop: rules"),
        ({"domains": ("asn:13335",), "leak": {}}, "only drop: rules"),
        ({"apps": (), "domains": ("drop:ads.example",), "leak": {}}, "needs 'apps'"),
        ({"leak": {"dns_via_target": False}}, "needs dns_via_target"),
    ],
)
async def test_isolation_refuses_what_it_cannot_enforce(
    tmp_path: Path, update: dict[str, Any], message: str
) -> None:
    config = isolated_config()
    torrents = config.policies[1]
    changes: dict[str, Any] = {k: v for k, v in update.items() if k != "leak"}
    changes["leak"] = torrents.leak.model_copy(update=update["leak"])
    config = config.model_copy(
        update={
            "policies": (
                config.policies[0],
                torrents.model_copy(update=changes),
                config.policies[2],
            )
        }
    )
    d, _, _ = daemon(tmp_path, config, launcher=FakeLauncher())
    with pytest.raises(ApiError, match=message):
        await d.start()


async def test_plan_and_status_carry_isolation(tmp_path: Path) -> None:
    d, backend, _ = daemon(tmp_path, isolated_config(), launcher=FakeLauncher())
    await d.start()
    try:
        assert [p.isolation for p in backend.last.policies] == ["none", "netns", "none"]
        status = await d.handle("status", {}, USER)
        assert [p["isolation"] for p in status["policies"]] == ["none", "netns", "none"]
    finally:
        await d.stop()


async def test_run_isolated_starts_as_the_caller_and_reports_exit(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    d, _, _ = daemon(tmp_path, isolated_config(), launcher=launcher)
    await d.start()
    try:
        started = await d.handle("run_isolated", {**RUN, "umask": 0o077}, USER)
        assert started == {"pid": 5000, "policy_id": 2}
        (command,) = launcher.commands
        assert command.policy_id == 2
        assert command.argv == ("qbittorrent",)
        assert (command.uid, command.gid, command.client_pid) == (1000, 1000, 4242)
        assert command.client_pidfd == _ALIVE_R
        assert (command.cwd, command.umask, dict(command.env)) == ("/home/u", 0o077, RUN["env"])
        # The placement slot is reserved like any placement.
        assert 2 in d._cgroup_policy_names

        with pytest.raises(ApiError) as e:
            await d.handle("wait_isolated", {"pid": 5000}, OTHER)
        assert e.value.code == "not_found"

        waiter = asyncio.ensure_future(d.handle("wait_isolated", {"pid": 5000}, USER))
        await asyncio.sleep(0)
        assert not waiter.done()
        launcher.children[0].exit.set_result(-15)
        assert await waiter == {"returncode": -15}
        with pytest.raises(ApiError):
            await d.handle("wait_isolated", {"pid": 5000}, USER)
    finally:
        await d.stop()


async def test_root_may_wait_for_any_isolated_command(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    d, _, _ = daemon(tmp_path, isolated_config(), launcher=launcher)
    await d.start()
    try:
        await d.handle("run_isolated", RUN, USER)
        launcher.children[0].exit.set_result(0)
        assert await d.handle("wait_isolated", {"pid": 5000}, ROOT) == {"returncode": 0}
    finally:
        await d.stop()


async def test_run_isolated_refusals(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    d, _, _ = daemon(tmp_path, isolated_config(), launcher=launcher)
    await d.start()
    r, w = os.pipe()
    os.close(w)
    gone = PeerCred(pid=4242, uid=1000, gid=1000, pidfd=r)
    try:
        for params, peer, code in [
            ({**RUN, "policy": "Japan"}, USER, "bad_request"),  # not isolated
            ({**RUN, "policy": "nope"}, USER, "not_found"),
            ({**RUN, "argv": []}, USER, "bad_request"),
            ({**RUN, "argv": ["a\0b"]}, USER, "bad_request"),
            ({**RUN, "env": {"A=B": "x"}}, USER, "bad_request"),
            ({**RUN, "env": {"A": 1}}, USER, "bad_request"),
            ({**RUN, "cwd": "relative"}, USER, "bad_request"),
            ({**RUN, "umask": 0o7777}, USER, "bad_request"),
            ({**RUN, "extra": 1}, USER, "bad_request"),
            (RUN, gone, "forbidden"),
            (RUN, PeerCred(pid=4242, uid=1000, gid=1000), "forbidden"),  # no pidfd
        ]:
            with pytest.raises(ApiError) as e:
                await d.handle("run_isolated", params, peer)
            assert e.value.code == code, params
        with pytest.raises(ApiError) as e:
            await d.handle("run_isolated", RUN, None)
        assert e.value.code == "forbidden"
        launcher.fail = OSError("no such namespace")
        with pytest.raises(ApiError) as e:
            await d.handle("run_isolated", RUN, USER)
        assert e.value.code == "unavailable"
        assert launcher.commands == []
    finally:
        os.close(r)
        await d.stop()


async def test_run_isolated_waits_for_the_namespace_to_be_installed(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    d, backend, _ = daemon(tmp_path, isolated_config(), launcher=launcher)
    backend.fail_apply = 100
    await d.start()
    try:
        with pytest.raises(ApiError) as e:
            await d.handle("run_isolated", RUN, USER)
        assert e.value.code == "unavailable"
        backend.fail_apply = 0
        await d.disable()
        with pytest.raises(ApiError, match="disabled"):
            await d.handle("run_isolated", RUN, USER)
        assert launcher.commands == []
    finally:
        await d.stop()


async def test_place_pid_api_refuses_isolated_policies(tmp_path: Path) -> None:
    d, _, _ = daemon(tmp_path, isolated_config(), launcher=FakeLauncher())
    await d.start()
    try:
        with pytest.raises(ApiError, match="uses isolation 'netns'"):
            await d.handle("place_pid", {"pid": 4242, "policy": "Torrents"}, USER)
        # The process watcher still governs selector matches with the cgroup
        # rules (kill switch included); only ``pyvpn run`` gets the namespace.
        await d.place_trusted(4242, 2)
    finally:
        await d.stop()


async def test_kill_switch_policy_still_launches_into_its_namespace(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    d, backend, targets = daemon(tmp_path, isolated_config(), launcher=launcher)
    await d.start()
    try:
        targets.push(up("nl", "tun0"))
        for _ in range(5):
            await asyncio.sleep(0)
        assert backend.last.policies[1].route == "dev"
        targets.push()
        for _ in range(5):
            await asyncio.sleep(0)
        assert backend.last.policies[1].route == "unreachable"
        await d.handle("run_isolated", RUN, USER)
        assert len(launcher.commands) == 1
    finally:
        await d.stop()


async def test_drop_rules_apply_to_isolated_policies(tmp_path: Path) -> None:
    config = isolated_config()
    torrents = config.policies[1].model_copy(update={"domains": ("drop:ads.example",)})
    config = config.model_copy(
        update={"policies": (config.policies[0], torrents, config.policies[2])}
    )
    d, backend, _ = daemon(tmp_path, config, launcher=FakeLauncher())
    await d.start()
    try:
        plan = backend.last.policies[1]
        assert plan.isolation == "netns"
        assert plan.dests is None  # still every destination through the target
        assert plan.drops is not None and plan.drops.drop
    finally:
        await d.stop()
