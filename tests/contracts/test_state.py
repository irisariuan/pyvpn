"""AppBinding exclusions (PLAN.md §3.3 and §3.4) and the fake app manager."""

import asyncio
from typing import Any

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
        exclude_uids=(0, 997, 4294967294),
    )
    assert binding.exclude_uids == (0, 997, 4294967294)


def test_any_process_binding_keeps_its_own_placement_cgroup() -> None:
    # PR #32: ``pyvpn run`` places processes in a destination-only policy's cgroup.
    binding = AppBinding(3, cgroup_paths=("pyvpn.slice/p-3",), any_process=True)
    assert binding.cgroup_paths == ("pyvpn.slice/p-3",)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"cgroup_paths": ("pyvpn.slice/p-2",)},
        {"cgroup_paths": ("user.slice/app.scope",)},
        {"cgroup_paths": ("pyvpn.slice/p-1", "pyvpn.slice/p-1")},
        {"uids": (1000,)},
    ],
)
def test_any_process_binding_rejects_ambiguous_selectors(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="any_process binding"):
        AppBinding(1, any_process=True, **kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"exclude_cgroup_paths": ("pyvpn.slice/x-1",)},
        {"exclude_uids": (997,)},
        {"cgroup_paths": ("pyvpn.slice/p-1",), "exclude_uids": (997,)},
    ],
)
def test_exclusions_need_any_process(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="any_process"):
        AppBinding(1, **kwargs)


@pytest.mark.parametrize(
    "path",
    [
        "",
        " ",
        "/",
        "//",
        "/system.slice/a.service",
        "system.slice/a.service/",
        "system.slice//a.service",
        "system.slice/../a.service",
        "./a.service",
        "system.slice/a b.service",
        "system.slice/a.service\n",
    ],
)
def test_malformed_exclusion_path_rejected(path: str) -> None:
    with pytest.raises(ValueError, match="exclude_cgroup_paths"):
        AppBinding(1, any_process=True, exclude_cgroup_paths=(path,))


@pytest.mark.parametrize(
    "path",
    [
        'system.slice/a"b.service',  # double quote
        "system.slice/a\\b.service",  # backslash
        "system.slice/a;b.service",  # semicolon
        "system.slice/a\x00b.service",  # non-printable (control)
        "system.slice/a\u200bb.service",  # non-printable (zero-width space)
    ],
    ids=["quote", "backslash", "semicolon", "control", "format"],
)
def test_exclusion_path_rejects_what_nft_cannot_quote(path: str) -> None:
    with pytest.raises(ValueError, match="nft cannot quote"):
        AppBinding(1, any_process=True, exclude_cgroup_paths=(path,))


def test_duplicate_exclusion_path_rejected() -> None:
    with pytest.raises(ValueError, match="duplicates"):
        AppBinding(1, any_process=True, exclude_cgroup_paths=("pyvpn.slice/x-1",) * 2)


@pytest.mark.parametrize("uids", [(-1,), (4294967295,), (True,), (997, 997)])
def test_bad_exclusion_uids_rejected(uids: tuple[int, ...]) -> None:
    with pytest.raises(ValueError, match="exclude_uids"):
        AppBinding(1, any_process=True, exclude_uids=uids)


def test_destination_only_policy_with_exclusions_is_valid_config() -> None:
    policy = Policy(
        name="corp",
        targets=("jp",),
        domains=("cidr:203.0.113.0/24",),
        exclude_apps=(AppSelector(name="openvpn"),),
    )
    assert not policy.apps and policy.exclude_apps


def test_fake_maps_each_exclusion_selector_kind() -> None:
    policy = Policy(
        name="corp",
        targets=("jp",),
        domains=("cidr:203.0.113.0/24",),
        exclude_apps=(
            AppSelector(uid=997),
            AppSelector(user="openvpn"),
            AppSelector(unit="mullvad-daemon.service"),
            AppSelector(flatpak="com.example.Vpn"),
            AppSelector(snap="examplevpn"),
            "group:vpn",
        ),
    )
    groups = (
        AppGroup(name="vpn", apps=(AppSelector(exe="/usr/sbin/openvpn"), AppSelector(name="wg"))),
    )
    apps = FakeAppManager(
        cgroups={
            ("unit", "mullvad-daemon.service"): "system.slice/mullvad-daemon.service",
            ("flatpak", "com.example.Vpn"): "user.slice/app-flatpak-com.example.Vpn-1.scope",
            ("snap", "examplevpn"): "system.slice/snap.examplevpn.daemon.service",
        },
        users={"openvpn": 994},
    )
    binding = asyncio.run(apps.bind(3, policy, groups))
    assert binding == AppBinding(
        3,
        any_process=True,
        exclude_cgroup_paths=(
            "system.slice/mullvad-daemon.service",
            "user.slice/app-flatpak-com.example.Vpn-1.scope",
            "system.slice/snap.examplevpn.daemon.service",
            "pyvpn.slice/x-4",  # exe and name share the moved-process cgroup
        ),
        exclude_uids=(994, 997),
    )
    assert apps.unresolved == []


def test_fake_gives_no_exemption_for_unresolved_selectors() -> None:
    policy = Policy(
        name="corp",
        targets=("jp",),
        domains=("corp.example",),
        exclude_apps=(AppSelector(unit="gone.service"), AppSelector(user="nobody-here")),
    )
    apps = FakeAppManager()
    binding = asyncio.run(apps.bind(2, policy, ()))
    assert binding == AppBinding(2, any_process=True)
    assert [sel for _, sel in apps.unresolved] == list(policy.exclude_apps)


def test_fake_binds_no_exclusions_without_exclude_apps() -> None:
    policy = Policy(name="corp", targets=("jp",), domains=("corp.example",))
    binding = asyncio.run(FakeAppManager().bind(2, policy, ()))
    assert binding == AppBinding(2, any_process=True)
