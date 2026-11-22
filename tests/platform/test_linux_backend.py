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
        self.fail = False

    async def __call__(self, script: str) -> None:
        if self.fail:
            raise RuntimeError("nft: simulated failure")
        self.scripts.append(script)
        self.log.append("nft delete" if "delete table" in script else "nft add")


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


def test_apply_installs_routes_then_nft_then_prunes(cgroups: Path) -> None:
    backend, nft, nl, log = make(cgroups)
    asyncio.run(backend.apply(RoutingPlan((policy(1), policy(2)))))
    log.clear()
    asyncio.run(backend.apply(RoutingPlan((policy(1, route="unreachable", interface=None),))))

    nft_at = log.index("nft delete")
    assert all(i < nft_at for i, e in enumerate(log) if "replace" in e or "add" in e)
    assert all(i > nft_at for i, e in enumerate(log) if " del " in e)
    assert {r.kind for r in nl.routes()} == {"unreachable"}
    assert {r.table for r in nl.rules()} == {1001}
    assert "reject" in nft.scripts[-1]


def test_failed_nft_restores_previous_routes(cgroups: Path) -> None:
    backend, nft, nl, _ = make(cgroups)
    asyncio.run(backend.apply(RoutingPlan((policy(1),))))
    before = (sorted(nl.rules(), key=repr), sorted(nl.routes(), key=repr))

    nft.fail = True
    with pytest.raises(RuntimeError, match="simulated"):
        asyncio.run(backend.apply(RoutingPlan((policy(1, interface="tun0"), policy(2)))))
    assert (sorted(nl.rules(), key=repr), sorted(nl.routes(), key=repr)) == before


def test_failed_first_apply_keeps_unknown_previous_rules(cgroups: Path) -> None:
    """Rules a previous daemon left must survive: its nft table is still loaded."""
    backend, nft, nl, _ = make(cgroups)
    asyncio.run(
        LinuxBackend(nft=FakeNft([]), netlink=nl, cgroup_root=cgroups).apply(
            RoutingPlan((policy(2),))
        )
    )
    nft.fail = True
    with pytest.raises(RuntimeError):
        asyncio.run(backend.apply(RoutingPlan((policy(1),))))
    assert 1002 in {r.table for r in nl.rules()}


def test_invalid_plan_changes_nothing(cgroups: Path) -> None:
    backend, nft, _, log = make(cgroups)
    with pytest.raises(ValueError):
        asyncio.run(backend.apply(RoutingPlan((policy(1, interface=None),))))
    assert log == [] and nft.scripts == []


def test_missing_cgroups_are_left_out_of_the_ruleset(cgroups: Path) -> None:
    backend, nft, _, _ = make(cgroups)
    apps = AppBinding(1, cgroup_paths=(policy_cgroup(1), "system.slice/gone.service"))
    asyncio.run(backend.apply(RoutingPlan((policy(1, apps=apps),))))
    assert '"pyvpn.slice/p-1"' in nft.scripts[-1]
    assert "gone.service" not in nft.scripts[-1]


def test_add_to_set_loads_only_elements(cgroups: Path) -> None:
    from ipaddress import IPv4Network

    backend, nft, _, _ = make(cgroups)
    asyncio.run(backend.add_to_set(DestSet(1, frozenset({IPv4Network("192.0.2.0/24")}))))
    assert nft.scripts == ["add element inet pyvpn p1_v4 { 192.0.2.0/24 }\n"]
    asyncio.run(backend.add_to_set(DestSet(1)))
    assert len(nft.scripts) == 1


def test_teardown_stops_marking_before_removing_routes(cgroups: Path) -> None:
    backend, nft, nl, log = make(cgroups)
    asyncio.run(backend.apply(RoutingPlan((policy(1),))))
    log.clear()
    asyncio.run(backend.teardown())
    assert log[0] == "nft delete"
    assert nl.rules() == [] and nl.routes() == []
    assert nft.scripts[-1] == "add table inet pyvpn\ndelete table inet pyvpn\n"
