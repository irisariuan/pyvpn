"""LinuxBackend ordering and failure handling with fake nft and netlink (pure)."""

from __future__ import annotations

import asyncio
import sys
from ipaddress import IPv4Network
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from pyvpn.apps.cgroups import CgroupError, CgroupManager
from pyvpn.config.models import LeakSettings
from pyvpn.constants import (
    NFT_TABLE,
    excluded_cgroup,
    policy_cgroup,
    policy_mark,
    policy_rule_pref,
    policy_table,
)
from pyvpn.netfilter.ruleset import ROUTE_GUARD_TABLE
from pyvpn.platform.base import Backend, Capabilities
from pyvpn.platform.linux import backend as linux_backend
from pyvpn.platform.linux.backend import LinuxBackend, NftError, NftOutcomeUnknown
from pyvpn.routing.plan import build_route_plan
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


def proc_sys(root: Path, *, ipv6: bool = True) -> Path:
    """A fake /proc/sys: unit tests never touch the real one."""
    proc = root / "_proc"
    knob = proc / "net/ipv4/conf/all/src_valid_mark"
    if not knob.exists():
        knob.parent.mkdir(parents=True)
        knob.write_text("0\n")
    if ipv6:
        (proc / "net/ipv6").mkdir(exist_ok=True)
    return proc


def make(
    cgroups: Path, *, ipv6: bool = True
) -> tuple[LinuxBackend, FakeNft, FakeNetlink, list[str]]:
    log: list[str] = []
    nft, nl = FakeNft(log), FakeNetlink(log)
    backend = LinuxBackend(
        nft=nft, netlink=nl, cgroup_root=cgroups, proc_sys=proc_sys(cgroups, ipv6=ipv6)
    )
    return backend, nft, nl, log


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


def test_run_nft_terminates_and_reaps_timed_out_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    spawn = asyncio.create_subprocess_exec

    async def start_slow_nft(*args: str, **kwargs: object) -> asyncio.subprocess.Process:
        assert args == ("nft", "-f", "-")
        return await spawn(sys.executable, "-c", "import time; time.sleep(60)", **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", start_slow_nft)
    monkeypatch.setattr(linux_backend, "_NFT_TIMEOUT", 0.05)
    with pytest.raises(NftOutcomeUnknown, match="timed out") as caught:
        asyncio.run(linux_backend.run_nft(""))
    assert caught.value.process is not None
    assert caught.value.process.returncode is not None


@pytest.mark.parametrize("committed", [True, False])
@pytest.mark.parametrize("teardown", [True, False])
def test_final_nft_timeout_uses_kernel_readback(
    cgroups: Path, committed: bool, teardown: bool
) -> None:
    log: list[str] = []
    nft, nl = FakeNft(log), FakeNetlink(log)
    timeout = False
    old, new = RoutingPlan((policy(1),)), RoutingPlan((policy(2),))
    expected = build_route_plan(RoutingPlan() if teardown else new)

    async def load(script: str) -> None:
        if timeout and script.startswith("add table inet pyvpn\n"):
            if committed:
                await nft(script)
            raise NftOutcomeUnknown("nft timed out")
        await nft(script)

    async def read_tables() -> set[str]:
        assert set(nl.routes()) == set(expected.routes)
        assert set(nl.rules()) == set(expected.rules)
        log.append("read nft tables")
        if nft.guarded:
            return {NFT_TABLE, ROUTE_GUARD_TABLE}
        return set() if teardown else {NFT_TABLE}

    backend = LinuxBackend(
        nft=load,
        nft_tables=read_tables,
        netlink=nl,
        cgroup_root=cgroups,
        proc_sys=proc_sys(cgroups),
    )

    async def scenario() -> None:
        nonlocal timeout
        await backend.apply(old)
        previous = build_route_plan(old)
        timeout = True
        operation = backend.teardown() if teardown else backend.apply(new)
        if committed:
            await operation
            assert set(nl.routes()) == set(expected.routes)
            assert set(nl.rules()) == set(expected.rules)
            assert log[-2:] == ["nft commit", "read nft tables"]
        else:
            with pytest.raises(NftOutcomeUnknown, match="timed out"):
                await operation
            assert set(nl.routes()) == set(previous.routes)
            assert set(nl.rules()) == set(previous.rules)
            assert log.index("read nft tables") < log.index("nft release")
        assert not nft.guarded
        timeout = False
        await backend.teardown()

    asyncio.run(scenario())


@pytest.mark.parametrize(("unreaped", "committed"), [(True, False), (False, False), (False, True)])
def test_unconfirmed_nft_commit_keeps_routes_until_guarded_recovery(
    cgroups: Path, unreaped: bool, committed: bool
) -> None:
    log: list[str] = []
    nft, nl = FakeNft(log), FakeNetlink(log)
    process = Mock(returncode=None)
    read_tables = AsyncMock(side_effect=NftError("read-back failed"))
    timeout = False
    learned = DestSet(1, frozenset({IPv4Network("192.0.2.0/24")}))
    old = RoutingPlan((policy(1, dests=DestSet(1)),))
    new = RoutingPlan((policy(2),))

    async def load(script: str) -> None:
        if timeout and script.startswith("add table inet pyvpn\n"):
            if committed:
                await nft(script)
            raise NftOutcomeUnknown("nft timed out", process if unreaped else None)
        await nft(script)

    backend = LinuxBackend(
        nft=load,
        nft_tables=read_tables,
        netlink=nl,
        cgroup_root=cgroups,
        proc_sys=proc_sys(cgroups),
    )

    async def scenario() -> None:
        nonlocal timeout
        await backend.apply(old)
        await backend.add_to_set(learned)
        timeout = True
        with pytest.raises(NftError, match="could not verify nft transaction"):
            await backend.apply(new)
        assert nft.guarded is not committed and "nft release" not in log
        assert set(nl.routes()) == set(build_route_plan(new).routes)
        assert read_tables.await_count == (0 if unreaped else 1)
        with pytest.raises(NftError, match="before publishing destinations"):
            await backend.add_to_set(learned)

        timeout = False
        if unreaped:
            log.clear()
            with pytest.raises(NftError, match="still exiting"):
                await backend.recheck_cgroups()
            assert not log
            process.returncode = -9
        assert await backend.recheck_cgroups()
        assert set(nl.routes()) == set(build_route_plan(old).routes)
        assert not nft.guarded
        assert "elements = { 192.0.2.0/24 }" in nft.scripts[-1]
        assert not await backend.recheck_cgroups()
        await backend.teardown()

    asyncio.run(scenario())


def test_failed_first_apply_keeps_unknown_previous_rules(cgroups: Path) -> None:
    """Rules a previous daemon left must survive: its nft table is still loaded."""
    backend, nft, nl, _ = make(cgroups)
    asyncio.run(
        LinuxBackend(
            nft=FakeNft([]), netlink=nl, cgroup_root=cgroups, proc_sys=proc_sys(cgroups)
        ).apply(RoutingPlan((policy(2),)))
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

        backend = LinuxBackend(
            nft=blocked_commit, netlink=nl, cgroup_root=cgroups, proc_sys=proc_sys(cgroups)
        )

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


def test_apply_enables_src_valid_mark(cgroups: Path) -> None:
    backend, _, _, _ = make(cgroups)
    asyncio.run(backend.apply(RoutingPlan((policy(1),))))
    knob = cgroups / "_proc/net/ipv4/conf/all/src_valid_mark"
    assert knob.read_text().strip() == "1"
    asyncio.run(backend.teardown())
    assert knob.read_text().strip() == "1"  # other tunnels may rely on it


def test_kernel_without_ipv6_gets_only_ipv4_rules_and_routes(cgroups: Path) -> None:
    backend, nft, nl, _ = make(cgroups, ipv6=False)
    asyncio.run(backend.apply(RoutingPlan((policy(1, leak=LeakSettings(ipv6="block")),))))
    assert {r.version for r in nl.rules()} == {4}
    assert {r.version for r in nl.routes()} == {4}
    assert "meta nfproto ipv6 reject" in nft.scripts[-1]


def test_recreated_cgroup_is_reapplied_with_learned_destinations(cgroups: Path) -> None:
    from ipaddress import IPv4Network

    backend, nft, _, _ = make(cgroups)
    ids: dict[str, int] = {policy_cgroup(1): 100}
    backend._cgroup_id = ids.get  # type: ignore[method-assign]

    async def scenario() -> None:
        await backend.apply(RoutingPlan((policy(1, dests=DestSet(1)),)))
        learned = DestSet(1, frozenset({IPv4Network("192.0.2.0/24")}))
        await backend.add_to_set(learned)
        assert not await backend.recheck_cgroups()
        loads = len(nft.scripts)

        del ids[policy_cgroup(1)]  # removed: wait, an apply would be refused
        assert not await backend.recheck_cgroups()
        ids[policy_cgroup(1)] = 101  # created again with a new id
        assert await backend.recheck_cgroups()
        assert len(nft.scripts) > loads
        assert "elements = { 192.0.2.0/24 }" in nft.scripts[-1]
        assert not await backend.recheck_cgroups()

        await backend.teardown()
        ids[policy_cgroup(1)] = 102
        assert not await backend.recheck_cgroups()  # nothing installed

    asyncio.run(scenario())


def test_watcher_reapplies_in_the_background(cgroups: Path) -> None:
    backend, nft, _, _ = make(cgroups)
    backend._cgroup_poll = 0.01
    ids = {policy_cgroup(1): 1}
    backend._cgroup_id = ids.get  # type: ignore[method-assign]

    async def scenario() -> None:
        await backend.apply(RoutingPlan((policy(1),)))
        loads = len(nft.scripts)
        ids[policy_cgroup(1)] = 2
        for _ in range(100):
            await asyncio.sleep(0.01)
            if len(nft.scripts) > loads:
                break
        assert len(nft.scripts) > loads
        await backend.teardown()

    asyncio.run(scenario())


def test_watcher_logs_once_per_failure_streak(
    cgroups: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    backend, _, _, _ = make(cgroups)
    backend._cgroup_poll = 0
    first = RuntimeError("first failure")
    recheck = AsyncMock(
        side_effect=[first, first, False, RuntimeError("later failure"), asyncio.CancelledError()]
    )
    monkeypatch.setattr(backend, "recheck_cgroups", recheck)

    async def scenario() -> None:
        with pytest.raises(asyncio.CancelledError):
            await backend._watch_cgroups()

    asyncio.run(scenario())
    assert recheck.await_count == 5
    errors = [str(record.exc_info[1]) for record in caplog.records if record.exc_info]
    assert errors == ["first failure", "later failure"]


class FakeCgroups(CgroupManager):
    def create(self, policy_id: int) -> Path:
        path = super().create(policy_id)
        (path / "cgroup.procs").touch()
        return path


@pytest.mark.parametrize("commit_fails", [False, True])
def test_placement_reinstalls_rules_after_slice_recreation(
    cgroups: Path, commit_fails: bool
) -> None:
    backend, nft, _, log = make(cgroups)
    groups = FakeCgroups(cgroups)
    procs = groups.path_for(1) / "cgroup.procs"

    def verify_peer() -> None:
        assert log[-1] == "nft commit"
        assert procs.read_text() == ""
        assert "elements = { 192.0.2.0/24 }" in nft.scripts[-1]

    async def scenario() -> None:
        await backend.apply(RoutingPlan((policy(1, dests=DestSet(1)), policy(2))))
        await backend.add_to_set(DestSet(1, frozenset({IPv4Network("192.0.2.0/24")})))
        groups.slice.rename(cgroups / "previous-slice")
        if commit_fails:
            nft.fail_on = "add table inet pyvpn\n"
            with pytest.raises(CgroupError, match="could not reinstall routing rules"):
                await backend.place_policy_pid(groups, 123, 1, verify_peer)
            assert procs.read_text() == ""
            nft.fail_on = None
        await backend.place_policy_pid(groups, 123, 1, verify_peer)
        assert procs.read_text() == "123\n"
        assert groups.path_for(2).is_dir()
        await backend.teardown()

    asyncio.run(scenario())


def test_placement_refuses_cgroup_replaced_after_rules_commit(cgroups: Path) -> None:
    backend, _, _, _ = make(cgroups)
    groups = FakeCgroups(cgroups)

    def replace_cgroup() -> None:
        groups.path_for(1).rename(cgroups / "previous-cgroup")
        groups.create(1)

    async def scenario() -> None:
        await backend.apply(RoutingPlan((policy(1),)))
        with pytest.raises(CgroupError, match=r"routing rules .* are stale"):
            await backend.place_policy_pid(groups, 123, 1, replace_cgroup)
        assert (groups.path_for(1) / "cgroup.procs").read_text() == ""
        await backend.teardown()

    asyncio.run(scenario())


def _dest_only(pid: int, *excluded: str) -> PolicyPlan:
    apps = AppBinding(pid, any_process=True, exclude_cgroup_paths=excluded)
    return policy(pid, apps=apps, dests=DestSet(pid))


def test_missing_exclusion_cgroup_rejects_the_plan(cgroups: Path) -> None:
    backend, nft, _, log = make(cgroups)
    plan = RoutingPlan((_dest_only(2, excluded_cgroup([2])),))
    with pytest.raises(ValueError, match=r"x-2"):
        asyncio.run(backend.apply(plan))
    assert log == [] and nft.scripts == []


def test_listed_and_idle_exclusion_cgroups_are_known(cgroups: Path) -> None:
    listed, idle = excluded_cgroup([2]), excluded_cgroup([1, 2])
    for path in (listed, idle, "pyvpn.slice/not-an-exclusion"):
        (cgroups / path).mkdir()
    backend, nft, _, _ = make(cgroups)
    asyncio.run(backend.apply(RoutingPlan((policy(1), _dest_only(2, listed)))))
    script = nft.scripts[-1]
    for path in (listed, idle):
        assert f'socket cgroupv2 level 2 "{path}" return' in script
    assert "not-an-exclusion" not in script


def test_idle_exclusion_cgroup_appearing_or_leaving_is_reapplied(cgroups: Path) -> None:
    backend, nft, _, _ = make(cgroups)
    idle = cgroups / excluded_cgroup([2])

    async def scenario() -> None:
        await backend.apply(RoutingPlan((policy(1),)))
        assert not await backend.recheck_cgroups()
        idle.mkdir()  # app manager withholds it while revalidating members
        assert await backend.recheck_cgroups()
        assert excluded_cgroup([2]) in nft.scripts[-1]
        assert not await backend.recheck_cgroups()
        idle.rmdir()
        assert await backend.recheck_cgroups()
        assert excluded_cgroup([2]) not in nft.scripts[-1]
        await backend.teardown()

    asyncio.run(scenario())


def test_drop_answers_go_to_the_drop_set_and_survive_a_reapply(cgroups: Path) -> None:
    backend, nft, _, _ = make(cgroups)
    drop = DestSet(1, frozenset({IPv4Network("192.0.2.0/24")}), drop=True)
    route = DestSet(1, frozenset({IPv4Network("198.51.100.0/24")}))

    async def scenario() -> None:
        await backend.apply(
            RoutingPlan((policy(1, dests=DestSet(1), drops=DestSet(1, drop=True)),))
        )
        await backend.add_to_set(drop)
        assert nft.scripts[-1] == "add element inet pyvpn p1_drop_v4 { 192.0.2.0/24 }\n"
        await backend.add_to_set(route)
        assert nft.scripts[-1] == "add element inet pyvpn p1_v4 { 198.51.100.0/24 }\n"
        assert backend._plan is not None
        (kept,) = backend._plan.policies
        assert kept.drops == drop and kept.dests == route
        await backend.teardown()

    asyncio.run(scenario())
