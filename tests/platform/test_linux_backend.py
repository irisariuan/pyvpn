"""LinuxBackend ordering and failure handling with fake nft and netlink (pure)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pyvpn.config.models import LeakSettings
from pyvpn.constants import policy_cgroup, policy_mark, policy_rule_pref, policy_table
from pyvpn.platform.base import Backend, Capabilities
from pyvpn.platform.linux.backend import LinuxBackend
from pyvpn.state import AppBinding, DestSet, PolicyPlan, RoutingPlan
from tests.routing._fakes import FakeNetlink


class FakeNft:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.scripts: list[str] = []
        self.fail_on: str | None = None
        self.guarded = False

    async def __call__(self, script: str) -> None:
        if self.fail_on is not None and script.startswith(self.fail_on):
            raise RuntimeError("nft: simulated failure")
        self.scripts.append(script)
        if "add chain inet pyvpn_guard output" in script:
            self.log.append("nft guard")
            self.guarded = True
        elif "delete table inet pyvpn_guard" in script:
            self.log.append(
                "nft commit" if script.startswith("add table inet pyvpn\n") else "nft release"
            )
            self.guarded = False
        else:
            self.log.append("nft update")


def policy(pid: int = 1, **kw: object) -> PolicyPlan:
    base: dict[str, object] = {
        "policy_id": pid,
        "mark": policy_mark(pid),
        "table": policy_table(pid),
        "rule_pref": policy_rule_pref(pid),
        "route": "dev",
        "interface": "wg-jp",
        "gateway": None,
        "apps": AppBinding(pid, cgroup_paths=(policy_cgroup(pid),)),
        "dests": None,
        "leak": LeakSettings(),
        "dns_stub_port": None,
    }
    base.update(kw)
    return PolicyPlan(**base)  # type: ignore[arg-type]


@pytest.fixture
def cgroups(tmp_path: Path) -> Path:
    for pid in (1, 2):
        (tmp_path / policy_cgroup(pid)).mkdir(parents=True)
    return tmp_path


def make(cgroups: Path) -> tuple[LinuxBackend, FakeNft, FakeNetlink, list[str]]:
    log: list[str] = []
    nft, nl = FakeNft(log), FakeNetlink(log)
    return LinuxBackend(nft=nft, netlink=nl, cgroup_root=cgroups), nft, nl, log


def test_constructible_without_arguments_and_reports_capabilities() -> None:
    backend: Backend = LinuxBackend()
    assert backend.capabilities == Capabilities(transparent=True, per_app_dns=True)


def test_apply_guards_route_changes_until_nft_commit(cgroups: Path) -> None:
    backend, nft, nl, log = make(cgroups)
    asyncio.run(backend.apply(RoutingPlan((policy(1), policy(2)))))
    log.clear()
    asyncio.run(backend.apply(RoutingPlan((policy(1, route="unreachable", interface=None),))))

    assert log[0] == "nft guard" and log[-1] == "nft commit"
    assert not nft.guarded
    assert {r.kind for r in nl.routes()} == {"unreachable"}
    assert {r.table for r in nl.rules()} == {1001}
    assert "reject" in nft.scripts[-1]


def test_failed_nft_restores_previous_routes(cgroups: Path) -> None:
    backend, nft, nl, _ = make(cgroups)
    asyncio.run(backend.apply(RoutingPlan((policy(1),))))
    before = (sorted(nl.rules(), key=repr), sorted(nl.routes(), key=repr))

    nft.fail_on = "add table inet pyvpn\n"
    with pytest.raises(RuntimeError, match="simulated"):
        asyncio.run(backend.apply(RoutingPlan((policy(1, interface="tun0"), policy(2)))))
    assert (sorted(nl.rules(), key=repr), sorted(nl.routes(), key=repr)) == before
    assert not nft.guarded


def test_failed_first_apply_keeps_unknown_previous_rules(cgroups: Path) -> None:
    """Rules a previous daemon left must survive: its nft table is still loaded."""
    backend, nft, nl, _ = make(cgroups)
    asyncio.run(
        LinuxBackend(nft=FakeNft([]), netlink=nl, cgroup_root=cgroups).apply(
            RoutingPlan((policy(2),))
        )
    )
    before = (nl.rules(), nl.routes())
    nft.fail_on = "add table inet pyvpn\n"
    with pytest.raises(RuntimeError):
        asyncio.run(backend.apply(RoutingPlan((policy(1),))))
    assert (nl.rules(), nl.routes()) == before
    assert nft.guarded


@pytest.mark.parametrize("failure", ["route replace v6 1001 unicast", "rule del v4 1002"])
def test_partial_route_failure_restores_old_state(cgroups: Path, failure: str) -> None:
    backend, nft, nl, log = make(cgroups)
    asyncio.run(backend.apply(RoutingPlan((policy(1), policy(2)))))
    before = (set(nl.rules()), set(nl.routes()))
    log.clear()
    nl.fail_on = failure

    with pytest.raises(OSError, match="simulated failure"):
        asyncio.run(backend.apply(RoutingPlan((policy(1, interface="tun0"),))))

    assert (set(nl.rules()), set(nl.routes())) == before
    assert log[0] == "nft guard" and log[-1] == "nft release"
    assert "nft commit" not in log
    assert not nft.guarded


def test_failed_rollback_keeps_guard_until_successful_apply(cgroups: Path) -> None:
    backend, nft, nl, _ = make(cgroups)
    old = RoutingPlan((policy(1),))
    new = RoutingPlan((policy(1, interface="tun0"), policy(2)))
    asyncio.run(backend.apply(old))
    nft.fail_on = "add table inet pyvpn\n"
    nl.fail_on = "rule del v4 1002"
    with pytest.raises(RuntimeError, match="simulated failure"):
        asyncio.run(backend.apply(new))
    assert nft.guarded

    nl.fail_on = None
    with pytest.raises(RuntimeError, match="simulated failure"):
        asyncio.run(backend.apply(old))
    assert nft.guarded

    nft.fail_on = None
    asyncio.run(backend.apply(old))
    assert not nft.guarded


def test_cancellation_waits_for_commit(cgroups: Path) -> None:
    async def run() -> None:
        entered, resume = asyncio.Event(), asyncio.Event()
        log: list[str] = []
        nft, nl = FakeNft(log), FakeNetlink(log)

        async def blocked_commit(script: str) -> None:
            if script.startswith("add table inet pyvpn\n"):
                entered.set()
                await resume.wait()
            await nft(script)

        backend = LinuxBackend(nft=blocked_commit, netlink=nl, cgroup_root=cgroups)

        async def apply_and_record() -> None:
            await backend.apply(RoutingPlan((policy(1),)))
            log.append("recorded commit")
            await asyncio.sleep(0)

        caller = asyncio.create_task(apply_and_record())
        await entered.wait()
        caller.cancel()
        await asyncio.sleep(0)
        assert nft.guarded and not caller.done()
        resume.set()
        with pytest.raises(asyncio.CancelledError):
            await caller
        assert log[-2:] == ["nft commit", "recorded commit"]
        assert not nft.guarded

    asyncio.run(run())


def test_invalid_plan_changes_nothing(cgroups: Path) -> None:
    backend, nft, _, log = make(cgroups)
    with pytest.raises(ValueError):
        asyncio.run(backend.apply(RoutingPlan((policy(1, interface=None),))))
    assert log == [] and nft.scripts == []


def test_missing_cgroup_rejects_the_plan_before_changes(cgroups: Path) -> None:
    backend, nft, _, log = make(cgroups)
    apps = AppBinding(1, cgroup_paths=(policy_cgroup(1), "system.slice/gone.service"))
    with pytest.raises(ValueError, match=r"gone\.service"):
        asyncio.run(backend.apply(RoutingPlan((policy(1, apps=apps),))))
    assert log == [] and nft.scripts == []


def test_add_to_set_loads_only_elements(cgroups: Path) -> None:
    from ipaddress import IPv4Network

    backend, nft, _, _ = make(cgroups)
    asyncio.run(backend.add_to_set(DestSet(1, frozenset({IPv4Network("192.0.2.0/24")}))))
    assert nft.scripts == ["add element inet pyvpn p1_v4 { 192.0.2.0/24 }\n"]
    asyncio.run(backend.add_to_set(DestSet(1)))
    assert len(nft.scripts) == 1


def test_teardown_keeps_guard_until_routes_are_removed(cgroups: Path) -> None:
    backend, nft, nl, log = make(cgroups)
    asyncio.run(backend.apply(RoutingPlan((policy(1),))))
    log.clear()
    asyncio.run(backend.teardown())
    assert log[0] == "nft guard" and log[-1] == "nft commit"
    assert nl.rules() == [] and nl.routes() == []
    assert nft.scripts[-1].startswith("add table inet pyvpn\ndelete table inet pyvpn\n")
    assert not nft.guarded
