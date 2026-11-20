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
        AppSelector(exe="/usr/bin/x"),
        AppSelector(name="x"),
        AppSelector(uid=1000),
        AppSelector(user="alice"),
        AppSelector(unit="x.service"),
        AppSelector(flatpak="org.x"),
        AppSelector(snap="foo"),
    ):
        assert matcher.matches(selector, process)


def _fake_proc(root: Path, pid: int, exe: str | None) -> Path:
    proc = root / str(pid)
    proc.mkdir()
    if exe is not None:
        (proc / "exe").symlink_to(exe)  # dangling: target is not on this host
    (proc / "comm").write_text("app\n")
    (proc / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
    (proc / "cgroup").write_text("0::/user.slice/app-flatpak-org.example.App-1.scope\n")
    return proc


def test_exe_outside_the_daemons_mount_namespace_still_matches(tmp_path: Path) -> None:
    _fake_proc(tmp_path, 7, "/app/bin/example-app")
    info = read_process(7, tmp_path)
    assert info is not None and info.exe == "/app/bin/example-app"
    assert SelectorMatcher.matches(AppSelector(flatpak="org.example.App"), info)


def test_deleted_exe_keeps_its_path(tmp_path: Path) -> None:
    _fake_proc(tmp_path, 8, "/usr/bin/foo (deleted)")
    info = read_process(8, tmp_path)
    assert info is not None
    assert SelectorMatcher.matches(AppSelector(exe="/usr/bin/foo"), info)


def test_process_without_exe_is_skipped(tmp_path: Path) -> None:
    _fake_proc(tmp_path, 9, None)  # exited, or a kernel thread
    assert read_process(9, tmp_path) is None
