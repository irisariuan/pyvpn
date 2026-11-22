"""AppBinding exclusions (PLAN.md §3.3 and §3.4) and the fake app manager."""

import asyncio

import pytest

from pyvpn.config.models import AppGroup, AppSelector, Policy
from pyvpn.state import AppBinding
from tests.fakes import FakeAppManager


def test_binding_defaults_have_no_exclusions() -> None:
    binding = AppBinding(1, any_process=True)
    assert binding.exclude_cgroup_paths == () and binding.exclude_uids == ()


def test_any_process_binding_accepts_exclusions() -> None:
    binding = AppBinding(
        1,
        any_process=True,
        exclude_cgroup_paths=("system.slice/openvpn-client@jp.service", "pyvpn.slice/x-1"),
        exclude_uids=(997,),
    )
    assert binding.exclude_uids == (997,)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"exclude_cgroup_paths": ("pyvpn.slice/x-1",)},
        {"exclude_uids": (997,)},
        {"cgroup_paths": ("pyvpn.slice/p-1",), "exclude_uids": (997,)},
    ],
)
def test_exclusions_need_any_process(kwargs: dict[str, tuple[str, ...] | tuple[int, ...]]) -> None:
    with pytest.raises(ValueError, match="any_process"):
        AppBinding(1, **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("path", ["", "/", "//"])
def test_empty_exclusion_path_rejected(path: str) -> None:
    with pytest.raises(ValueError, match="empty path"):
        AppBinding(1, any_process=True, exclude_cgroup_paths=(path,))


def test_destination_only_policy_with_exclusions_is_valid_config() -> None:
    policy = Policy(
        name="corp",
        targets=("jp",),
        domains=("cidr:203.0.113.0/24",),
        exclude_apps=(AppSelector(name="openvpn"),),
    )
    assert not policy.apps and policy.exclude_apps


def test_fake_binds_exclusions_of_destination_only_policy() -> None:
    policy = Policy(
        name="corp",
        targets=("jp",),
        domains=("cidr:203.0.113.0/24",),
        exclude_apps=(AppSelector(uid=997), "group:vpn"),
    )
    groups = (AppGroup(name="vpn", apps=(AppSelector(exe="/usr/sbin/openvpn"),)),)
    binding = asyncio.run(FakeAppManager().bind(3, policy, groups))
    assert binding == AppBinding(
        3,
        any_process=True,
        exclude_cgroup_paths=("pyvpn.slice/x-3",),
        exclude_uids=(997,),
    )


def test_fake_binds_no_exclusions_without_exclude_apps() -> None:
    policy = Policy(name="corp", targets=("jp",), domains=("corp.example",))
    binding = asyncio.run(FakeAppManager().bind(2, policy, ()))
    assert binding == AppBinding(2, any_process=True)
