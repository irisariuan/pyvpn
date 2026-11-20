from __future__ import annotations

from pathlib import Path

from pyvpn.apps.selectors import ProcessInfo, SelectorMatcher, read_process
from pyvpn.config.models import AppGroup, AppSelector, Policy


def test_reads_fake_proc_metadata(tmp_path: Path) -> None:
    proc = tmp_path / "123"
    proc.mkdir()
    binary = tmp_path / "foo"
    binary.write_text("binary")
    (proc / "exe").symlink_to(binary)
    (proc / "comm").write_text("foo\n")
    (proc / "status").write_text("Name:\tfoo\nUid:\t1000\t1000\t1000\t1000\n")
    (proc / "cgroup").write_text("0::/user.slice/app-flatpak-org.example.App.scope\n")
    info = read_process(123, tmp_path)
    assert info is not None
    assert info.exe == str(binary)
    assert info.uid == 1000
    assert info.flatpak == "org.example.App"


def test_groups_and_exclusions() -> None:
    groups = [AppGroup(name="browsers", apps=(AppSelector(name="firefox"),))]
    matcher = SelectorMatcher(groups)
    policy = Policy(
        name="p",
        targets=("t",),
        apps=("group:browsers",),
        exclude_apps=(AppSelector(uid=0),),
    )
    assert matcher.matches_policy(policy, ProcessInfo(1, name="firefox", uid=1000))
    assert not matcher.matches_policy(policy, ProcessInfo(2, name="firefox", uid=0))


def test_matches_selector_types() -> None:
    matcher = SelectorMatcher()
    process = ProcessInfo(
        10,
        exe="/usr/bin/x",
        name="x",
        uid=1000,
        user="alice",
        cgroup="/system.slice/x.service",
        flatpak="org.x",
        snap="foo",
    )
    for selector in (
        AppSelector(exe="/usr/bin/x"), AppSelector(name="x"), AppSelector(uid=1000),
        AppSelector(user="alice"), AppSelector(unit="x.service"),
        AppSelector(flatpak="org.x"), AppSelector(snap="foo"),
    ):
        assert matcher.matches(selector, process)
