"""Unit tests for the root-job preflight (no root, no host network)."""

from __future__ import annotations

import errno
import subprocess
from pathlib import Path

import pytest

from tests.ci import preflight


def test_cgroup2_problem_rejects_a_missing_mount(tmp_path: Path) -> None:
    problem = preflight.cgroup2_problem(tmp_path)
    assert problem is not None
    assert "cgroup v2" in problem


def test_cgroup2_problem_accepts_a_v2_mount(tmp_path: Path) -> None:
    (tmp_path / "cgroup.controllers").write_text("cpu memory\n")
    assert preflight.cgroup2_problem(tmp_path) is None


def test_cgroup_write_problem_accepts_a_writable_root(tmp_path: Path) -> None:
    assert preflight.cgroup_write_problem(tmp_path) is None
    assert list(tmp_path.iterdir()) == []


def test_cgroup_write_problem_reports_an_unwritable_root(tmp_path: Path) -> None:
    missing = tmp_path / "not-mounted"
    problem = preflight.cgroup_write_problem(missing)
    assert problem is not None
    assert str(missing) in problem


def test_cgroup_write_problem_explains_a_read_only_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deny(self: Path, *args: object, **kwargs: object) -> None:
        raise OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(Path, "mkdir", deny)
    problem = preflight.cgroup_write_problem(tmp_path)
    assert problem is not None
    assert "read-write" in problem


def test_netns_problem_reports_a_missing_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError(errno.ENOENT, "No such file or directory")

    monkeypatch.setattr(preflight.subprocess, "run", missing)
    problem = preflight.netns_problem()
    assert problem is not None
    assert "ip netns add" in problem


def test_netns_problem_shows_the_kernel_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def failed(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["ip"], 1, "", "mount --make-shared /run/netns failed: Operation not permitted"
        )

    monkeypatch.setattr(preflight.subprocess, "run", failed)
    problem = preflight.netns_problem()
    assert problem is not None
    assert "Operation not permitted" in problem


def test_cgroup_write_problem_reports_a_failed_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def busy(self: Path, *args: object, **kwargs: object) -> None:
        raise OSError(errno.EBUSY, "Device or resource busy")

    monkeypatch.setattr(Path, "rmdir", busy)
    problem = preflight.cgroup_write_problem(tmp_path)
    assert problem is not None
    assert "cannot remove" in problem


@pytest.fixture
def linux_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.sys, "platform", "linux")
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 0)


def test_problems_stops_after_a_prerequisite_failure(
    linux_root: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(preflight, "missing_tools", lambda tools=preflight.TOOLS: ["nft"])
    for probe in ("cgroup2_problem", "cgroup_write_problem", "netns_problem"):
        monkeypatch.setattr(preflight, probe, lambda *a, **k: pytest.fail("probe ran"))

    assert preflight.problems() == ["missing tool 'nft' on PATH"]


def test_problems_reports_a_missing_root(linux_root: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight, "missing_tools", lambda tools=preflight.TOOLS: [])
    problems = preflight.problems()
    assert any("needs root" in problem for problem in problems)


def test_missing_tools_lists_only_absent_binaries() -> None:
    assert preflight.missing_tools(("pyvpn-definitely-not-a-tool",)) == [
        "pyvpn-definitely-not-a-tool"
    ]


def test_missing_tools_finds_a_real_binary() -> None:
    assert preflight.missing_tools(("sh",)) == []
