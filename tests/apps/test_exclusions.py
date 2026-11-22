"""``exclude_apps`` enforcement (PLAN.md §3.3), on fake /proc and cgroup trees."""

from __future__ import annotations

import pwd
from pathlib import Path

import pytest

from pyvpn.apps.cgroups import CgroupManager
from pyvpn.apps.exclusions import config_exclusion_problems, unsupported_exclusions
from pyvpn.apps.manager import AppManager
from pyvpn.apps.selectors import ProcessInfo, SelectorMatcher, pyvpn_cgroup, read_process
from pyvpn.apps.watcher import ProcessWatcher
from pyvpn.config.models import AppGroup, AppSelector, Config, Policy, Target

USER_POLICY = Policy(
    name="vpn",
    targets=("t",),
    apps=(AppSelector(uid=1000),),
    exclude_apps=(AppSelector(name="steam"),),
)
BROWSER_POLICY = Policy(name="web", targets=("t",), apps=(AppSelector(name="firefox"),))


def fake_process(
    root: Path,
    pid: int,
    name: str,
    *,
    ppid: int = 1,
    uid: int = 1000,
    cgroup: str = "/user.slice",
) -> None:
    proc = root / str(pid)
    proc.mkdir(exist_ok=True)
    exe = root / f"bin-{name}"
    exe.write_text("x")
    if (proc / "exe").is_symlink():
        (proc / "exe").unlink()
    (proc / "exe").symlink_to(exe)
    (proc / "comm").write_text(f"{name}\n")
    (proc / "status").write_text(f"PPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    (proc / "cgroup").write_text(f"0::{cgroup}\n")


class Recorder:
    def __init__(self) -> None:
        self.placed: list[tuple[int, int]] = []
        self.excluded: list[tuple[int, frozenset[int]]] = []

    async def place(self, pid: int, policy_id: int) -> None:
        self.placed.append((pid, policy_id))

    async def exclude(self, pid: int, policy_ids: frozenset[int]) -> None:
        self.excluded.append((pid, policy_ids))


def watcher(root: Path, policies: list[Policy], rec: Recorder) -> ProcessWatcher:
    return ProcessWatcher(policies, rec.place, exclude_pid=rec.exclude, proc_root=root)


# --- matcher -----------------------------------------------------------------


def proc(name: str, uid: int = 1000) -> ProcessInfo:
    return ProcessInfo(pid=10, name=name, uid=uid)


def test_excluded_process_goes_to_its_exclusion_cgroup() -> None:
    m = SelectorMatcher()
    assert m.target([USER_POLICY], proc("bash"), "") == "pyvpn.slice/p-1"
    assert m.target([USER_POLICY], proc("steam"), "") == "pyvpn.slice/x-1"


def test_excluded_process_still_matches_other_policies() -> None:
    other = Policy(name="games", targets=("t",), apps=(AppSelector(name="steam"),))
    m = SelectorMatcher()
    assert m.target([USER_POLICY, other], proc("steam"), "") == "pyvpn.slice/p-2"


def test_process_inheriting_a_policy_cgroup_is_moved_out_when_excluded() -> None:
    # A firefox child that runs steam: steam does not match the policy's apps
    # but inherited its cgroup, so the exclusion must still move it out.
    policy = Policy(
        name="web",
        targets=("t",),
        apps=(AppSelector(name="firefox"),),
        exclude_apps=(AppSelector(name="steam"),),
    )
    m = SelectorMatcher()
    assert m.target([policy], proc("steam"), "pyvpn.slice/p-1") == "pyvpn.slice/x-1"
    assert m.target([policy], proc("helper"), "pyvpn.slice/p-1") == "pyvpn.slice/p-1"


def test_exemption_is_inherited_but_only_from_its_policies() -> None:
    m = SelectorMatcher()
    # A game steam started: uid 1000 matches the policy, but it inherits
    # steam's exemption from policy 1.
    assert m.target([USER_POLICY], proc("game"), "pyvpn.slice/x-1") == "pyvpn.slice/x-1"
    # Another policy whose apps match still takes it (fail closed).
    assert (
        m.target([USER_POLICY, BROWSER_POLICY], proc("firefox"), "pyvpn.slice/x-1")
        == "pyvpn.slice/p-2"
    )


def test_stale_exemption_is_revalidated() -> None:
    m = SelectorMatcher()
    plain = Policy(name="vpn", targets=("t",), apps=(AppSelector(uid=1000),))
    # Policy 1 no longer excludes anything: the x-1 member is placed again.
    assert m.target([plain], proc("game"), "pyvpn.slice/x-1") == "pyvpn.slice/p-1"
    # Policy 3 does not exist any more.
    assert m.target([plain], proc("game", uid=0), "pyvpn.slice/x-4") is None


def test_exclusion_by_group_and_each_selector_kind() -> None:
    group = AppGroup(name="vpn", apps=(AppSelector(exe="/usr/sbin/openvpn"),))
    policy = Policy(
        name="all",
        targets=("t",),
        apps=(AppSelector(uid=1000),),
        exclude_apps=("group:vpn", AppSelector(user="svc"), AppSelector(unit="x.service")),
    )
    m = SelectorMatcher((group,))
    assert m.target([policy], ProcessInfo(1, exe="/usr/sbin/openvpn", uid=1000), "")
    assert m.target([policy], ProcessInfo(1, uid=1000, user="svc"), "") == "pyvpn.slice/x-1"
    unit = ProcessInfo(1, uid=1000, cgroup="/system.slice/x.service")
    assert m.target([policy], unit, "") == "pyvpn.slice/x-1"
    assert m.target([policy], ProcessInfo(1, uid=1000, user="me"), "") == "pyvpn.slice/p-1"


def test_excluded_from_several_policies_names_all_of_them() -> None:
    second = Policy(
        name="b",
        targets=("t",),
        apps=(AppSelector(name="steam"),),
        exclude_apps=(AppSelector(uid=1000),),
    )
    assert SelectorMatcher().target([USER_POLICY, second], proc("steam"), "") == "pyvpn.slice/x-3"


def test_pyvpn_cgroup() -> None:
    assert pyvpn_cgroup("/pyvpn.slice/p-2\n") == "pyvpn.slice/p-2"
    assert pyvpn_cgroup("/pyvpn.slice/x-5") == "pyvpn.slice/x-5"
    assert pyvpn_cgroup("/pyvpn.slice/p-2/x-1") == ""
    assert pyvpn_cgroup("/user.slice") == ""


def test_read_process_reads_ppid(tmp_path: Path) -> None:
    fake_process(tmp_path, 42, "steam", ppid=7)
    info = read_process(42, tmp_path)
    assert info is not None and info.ppid == 7


# --- watcher -----------------------------------------------------------------


async def test_exec_of_excluded_app_in_policy_cgroup_moves_it_out(tmp_path: Path) -> None:
    # The bug this fixes: the user's session is in p-1, so steam started from
    # it inherited p-1 and stayed routed.
    fake_process(tmp_path, 50, "steam", cgroup="/pyvpn.slice/p-1")
    rec = Recorder()
    assert await watcher(tmp_path, [USER_POLICY], rec).handle_exec(50) is None
    assert rec.excluded == [(50, frozenset({1}))]
    assert rec.placed == []


async def test_excluded_app_is_never_placed(tmp_path: Path) -> None:
    fake_process(tmp_path, 50, "steam")
    fake_process(tmp_path, 51, "bash")
    rec = Recorder()
    await watcher(tmp_path, [USER_POLICY], rec).scan()
    assert rec.placed == [(51, 1)]
    assert rec.excluded == [(50, frozenset({1}))]


async def test_children_of_an_excluded_app_stay_excluded(tmp_path: Path) -> None:
    fake_process(tmp_path, 60, "game", ppid=50, cgroup="/pyvpn.slice/x-1")
    rec = Recorder()
    w = watcher(tmp_path, [USER_POLICY], rec)
    assert await w.handle_exec(60) is None
    assert rec.placed == [] and rec.excluded == []


async def test_scan_moves_existing_children_with_their_parent(tmp_path: Path) -> None:
    # Startup: steam and its game share steam's scope; firefox and its
    # content process share another. Children follow their parent.
    fake_process(tmp_path, 50, "steam", cgroup="/user.slice/steam.scope")
    fake_process(tmp_path, 60, "game", ppid=50, cgroup="/user.slice/steam.scope")
    fake_process(tmp_path, 70, "firefox", uid=0, cgroup="/user.slice/ff.scope")
    fake_process(tmp_path, 71, "content", ppid=70, uid=0, cgroup="/user.slice/ff.scope")
    fake_process(tmp_path, 72, "other", ppid=70, uid=0, cgroup="/user.slice/elsewhere")
    rec = Recorder()
    moved = await watcher(tmp_path, [USER_POLICY, BROWSER_POLICY], rec).scan()
    assert moved == 4
    assert sorted(rec.excluded) == [(50, frozenset({1})), (60, frozenset({1}))]
    assert sorted(rec.placed) == [(70, 2), (71, 2)]


async def test_without_exclusion_placement_the_process_stays_governed(tmp_path: Path) -> None:
    fake_process(tmp_path, 50, "steam", cgroup="/pyvpn.slice/p-1")
    rec = Recorder()
    w = ProcessWatcher([USER_POLICY], rec.place, proc_root=tmp_path)
    await w.handle_exec(50)
    assert rec.placed == [] and rec.excluded == []


async def test_watcher_moves_into_real_exclusion_cgroup(tmp_path: Path) -> None:
    procfs, cgroupfs = tmp_path / "proc", tmp_path / "cg"
    procfs.mkdir()
    fake_process(procfs, 50, "steam", cgroup="/pyvpn.slice/p-1")
    cgroups = CgroupManager(cgroupfs)

    async def exclude(pid: int, ids: frozenset[int]) -> None:
        cgroups.place_excluded(pid, ids)

    rec = Recorder()
    w = ProcessWatcher([USER_POLICY], rec.place, exclude_pid=exclude, proc_root=procfs)
    await w.handle_exec(50)
    assert (cgroupfs / "pyvpn.slice/x-1/cgroup.procs").read_text() == "50\n"


# --- app manager and cgroups --------------------------------------------------


async def test_app_policy_with_exclusions_precreates_its_exclusion_cgroup(tmp_path: Path) -> None:
    manager = AppManager(CgroupManager(tmp_path))
    await manager.bind(2, USER_POLICY, ())
    assert (tmp_path / "pyvpn.slice/x-2").is_dir()
    await manager.unbind(2)
    assert not (tmp_path / "pyvpn.slice/x-2").exists()


def test_busy_exclusion_cgroup_is_kept(tmp_path: Path) -> None:
    cgroups = CgroupManager(tmp_path)
    cgroups.place_excluded(50, {1, 3})
    cgroups.remove_excluded(3)  # non-empty (a member file stands in for procs)
    assert (tmp_path / "pyvpn.slice/x-5").is_dir()
    with pytest.raises(ValueError):
        cgroups.place_excluded(0, {1})


async def test_destination_only_policy_exempts_uid_and_user(tmp_path: Path) -> None:
    me = pwd.getpwuid(0).pw_name
    policy = Policy(
        name="corp",
        targets=("t",),
        domains=("cidr:203.0.113.0/24",),
        exclude_apps=(AppSelector(uid=997), AppSelector(user=me)),
    )
    binding = await AppManager(CgroupManager(tmp_path)).bind(1, policy, ())
    assert binding.any_process
    assert binding.exclude_uids == (0, 997)
    assert binding.exclude_cgroup_paths == ()


async def test_destination_only_policy_refuses_unknown_user(tmp_path: Path) -> None:
    policy = Policy(
        name="corp",
        targets=("t",),
        domains=("cidr:203.0.113.0/24",),
        exclude_apps=(AppSelector(user="no-such-user-pyvpn"),),
    )
    with pytest.raises(ValueError, match="does not exist"):
        await AppManager(CgroupManager(tmp_path)).bind(1, policy, ())


@pytest.mark.parametrize(
    "selector",
    [
        AppSelector(exe="/usr/sbin/openvpn"),
        AppSelector(name="openvpn"),
        AppSelector(unit="openvpn.service"),
        AppSelector(flatpak="com.example.Vpn"),
        AppSelector(snap="examplevpn"),
    ],
)
async def test_destination_only_policy_refuses_deferred_selectors(
    tmp_path: Path, selector: AppSelector
) -> None:
    policy = Policy(
        name="corp", targets=("t",), domains=("cidr:203.0.113.0/24",), exclude_apps=(selector,)
    )
    (problem,) = unsupported_exclusions(policy, ())
    assert "not supported on a policy without apps" in problem
    with pytest.raises(ValueError, match="not supported"):
        await AppManager(CgroupManager(tmp_path)).bind(1, policy, ())


def test_config_problems_expand_groups_and_skip_app_policies() -> None:
    config = Config(
        targets=(Target(name="t", interface="wg0"),),
        app_groups=(AppGroup(name="vpn", apps=(AppSelector(name="openvpn"),)),),
        policies=(
            USER_POLICY,
            Policy(
                name="corp",
                targets=("t",),
                domains=("cidr:203.0.113.0/24",),
                exclude_apps=("group:vpn", AppSelector(uid=1)),
            ),
        ),
    )
    (problem,) = config_exclusion_problems(config)
    assert problem.startswith("policy 'corp': exclude_apps name: 'openvpn'")
