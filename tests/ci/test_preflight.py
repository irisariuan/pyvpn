"""Unit tests for the root-job preflight (no root, no host network)."""

from __future__ import annotations

from pathlib import Path

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
    assert "read-write" in problem


def test_missing_tools_lists_only_absent_binaries() -> None:
    assert preflight.missing_tools(("pyvpn-definitely-not-a-tool",)) == [
        "pyvpn-definitely-not-a-tool"
    ]


def test_missing_tools_finds_a_real_binary() -> None:
    assert preflight.missing_tools(("sh",)) == []
