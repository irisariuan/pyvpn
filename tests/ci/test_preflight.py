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


def test_missing_tools_lists_only_absent_binaries() -> None:
    assert preflight.missing_tools(("pyvpn-definitely-not-a-tool",)) == [
        "pyvpn-definitely-not-a-tool"
    ]


def test_missing_tools_finds_a_real_binary() -> None:
    assert preflight.missing_tools(("sh",)) == []
