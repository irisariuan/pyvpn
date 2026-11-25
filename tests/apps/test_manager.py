from __future__ import annotations

from pathlib import Path

import pytest

from pyvpn.apps.cgroups import CgroupManager
from pyvpn.apps.manager import AppManager
from pyvpn.config.models import AppGroup, AppSelector, Policy


async def test_manager_exposes_cgroup_and_uid_binding(tmp_path: Path) -> None:
    manager = AppManager(CgroupManager(tmp_path))
    policy = Policy(name="p", targets=("t",), apps=(AppSelector(uid=1001),))
    binding = await manager.bind(1, policy, ())
    assert binding.cgroup_paths == ("pyvpn.slice/p-1",)
    assert binding.uids == (1001,)
    assert (tmp_path / "pyvpn.slice" / "p-1").is_dir()
    await manager.unbind(1)


async def test_domain_only_policy_is_any_process(tmp_path: Path) -> None:
    manager = AppManager(CgroupManager(tmp_path))
    policy = Policy(name="p", targets=("t",), domains=("example.com",))
    binding = await manager.bind(1, policy, ())
    assert binding.any_process
    assert binding.cgroup_paths == ("pyvpn.slice/p-1",)
    assert (tmp_path / "pyvpn.slice/p-1").is_dir()


async def test_group_uid_is_in_binding(tmp_path: Path) -> None:
    manager = AppManager(CgroupManager(tmp_path))
    policy = Policy(name="p", targets=("t",), apps=("group:users",))
    group = AppGroup(name="users", apps=(AppSelector(uid=42),))
    binding = await manager.bind(1, policy, (group,))
    assert binding.uids == (42,)


async def test_uid_exclusions_are_subtracted_from_the_uid_match(tmp_path: Path) -> None:
    manager = AppManager(CgroupManager(tmp_path))
    policy = Policy(
        name="p",
        targets=("t",),
        apps=(AppSelector(uid=1001), AppSelector(uid=1002)),
        exclude_apps=(AppSelector(uid=1001),),
    )
    binding = await manager.bind(1, policy, ())
    assert binding.uids == (1002,)
    assert binding.cgroup_paths == ("pyvpn.slice/p-1",)


async def test_name_exclusion_with_a_uid_selector_is_refused(tmp_path: Path) -> None:
    manager = AppManager(CgroupManager(tmp_path))
    policy = Policy(
        name="p",
        targets=("t",),
        apps=(AppSelector(uid=1001),),
        exclude_apps=(AppSelector(name="ssh"),),
    )
    with pytest.raises(ValueError, match="cannot be combined"):
        await manager.bind(1, policy, ())
