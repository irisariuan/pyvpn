"""``exclude_apps`` enforcement (PLAN.md §3.3), on fake /proc and cgroup trees."""

from __future__ import annotations

import pwd
from pathlib import Path

import pytest

from pyvpn.apps.cgroups import CgroupManager
from pyvpn.apps.exclusions import (
    config_exclusion_problems,
    exclusion_warnings,
    unsupported_exclusions,
)
from pyvpn.apps.manager import AppManager
from pyvpn.apps.watcher import ProcessWatcher
from pyvpn.config.models import AppGroup, AppSelector, Config, Policy, Target

USER_POLICY = Policy(
    name="vpn",
    targets=("t",),
    apps=(AppSelector(uid=1000),),
    exclude_apps=(AppSelector(name="steam"),),
)
GAMES_POLICY = Policy(name="games", targets=("t",), apps=(AppSelector(name="steam"),))
NAME_POLICY = Policy(
    name="vpn",
    targets=("t",),
    apps=(AppSelector(name="firefox"),),
    exclude_apps=(AppSelector(name="steam"),),
)


def fake_process(root: Path, pid: int, name: str, *, cgroup: str = "/user.slice") -> None:
    proc = root / str(pid)
    proc.mkdir(exist_ok=True)
    exe = root / f"bin-{name}"
    exe.write_text("x")
    (proc / "exe").symlink_to(exe)
    (proc / "comm").write_text(f"{name}\n")
    (proc / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
    (proc / "cgroup").write_text(f"0::{cgroup}\n")


class Recorder:
    def __init__(self) -> None:
        self.placed: list[tuple[int, int]] = []

    async def __call__(self, pid: int, policy_id: int) -> None:
        self.placed.append((pid, policy_id))


# --- policies with apps: exclusions filter placement only ---------------------


async def test_excluded_app_is_never_placed(tmp_path: Path) -> None:
    fake_process(tmp_path, 50, "steam")
    fake_process(tmp_path, 51, "bash")
    place = Recorder()
    await ProcessWatcher([USER_POLICY], place, proc_root=tmp_path).scan()
    assert place.placed == [(51, 1)]


async def test_excluded_app_still_joins_another_policy(tmp_path: Path) -> None:
    fake_process(tmp_path, 50, "steam")
    place = Recorder()
    watcher = ProcessWatcher([USER_POLICY, GAMES_POLICY], place, proc_root=tmp_path)
    assert await watcher.handle_exec(50) == 2
    assert place.placed == [(50, 2)]


async def test_excluded_app_in_the_policy_cgroup_is_never_moved_out(tmp_path: Path) -> None:
    # Started from a process the policy already routes: it stays governed.
    # Moving it out would exempt whatever it executes next (fail closed).
    fake_process(tmp_path, 50, "steam", cgroup="/pyvpn.slice/p-1")
    place = Recorder()
    assert await ProcessWatcher([USER_POLICY], place, proc_root=tmp_path).handle_exec(50) is None
    assert place.placed == []


async def test_name_app_policy_with_exclusions_is_placed_by_the_watcher(tmp_path: Path) -> None:
    binding = await AppManager(CgroupManager(tmp_path)).bind(1, NAME_POLICY, ())
    assert binding.uids == ()
    assert binding.cgroup_paths == ("pyvpn.slice/p-1",)
    assert not (tmp_path / "pyvpn.slice/x-1").exists()


async def test_uid_exclusion_is_subtracted_from_the_uid_match(tmp_path: Path) -> None:
    policy = Policy(
        name="vpn",
        targets=("t",),
        apps=(AppSelector(uid=1000),),
        exclude_apps=(AppSelector(uid=1000),),
    )
    binding = await AppManager(CgroupManager(tmp_path)).bind(1, policy, ())
    assert binding.uids == ()
    assert binding.cgroup_paths == ("pyvpn.slice/p-1",)


async def test_name_exclusion_with_a_uid_selector_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        await AppManager(CgroupManager(tmp_path)).bind(1, USER_POLICY, ())


def test_app_policy_exclusions_warn_that_they_only_filter_placement() -> None:
    config = Config(
        targets=(Target(name="t", interface="wg0"),),
        policies=(NAME_POLICY, GAMES_POLICY),
    )
    (warning,) = exclusion_warnings(config)
    assert warning.startswith("policy 'vpn': exclude_apps only keep matching processes")
    assert config_exclusion_problems(config) == []


def test_unknown_user_in_exclusions_is_reported() -> None:
    policy = Policy(
        name="vpn",
        targets=("t",),
        apps=(AppSelector(name="firefox"),),
        exclude_apps=(AppSelector(user="no-such-user-pyvpn"),),
    )
    (problem,) = unsupported_exclusions(policy, ())
    assert "does not exist" in problem


# --- policies with only domains: uid/user only -------------------------------


async def test_destination_only_policy_exempts_uid_and_user(tmp_path: Path) -> None:
    root = pwd.getpwuid(0).pw_name
    policy = Policy(
        name="corp",
        targets=("t",),
        domains=("cidr:203.0.113.0/24",),
        exclude_apps=(AppSelector(uid=997), AppSelector(user=root)),
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
            NAME_POLICY,
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
