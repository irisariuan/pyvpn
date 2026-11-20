from __future__ import annotations

from pathlib import Path

import pytest

from pyvpn.apps.cgroups import CgroupError, CgroupManager


def test_create_and_place_pid_under_policy_cgroup(tmp_path: Path) -> None:
    manager = CgroupManager(tmp_path)
    path = manager.place_pid(123, 2)
    assert path == tmp_path / "pyvpn.slice" / "p-2"
    assert (path / "cgroup.procs").read_text() == "123\n"


def test_rejects_invalid_policy_and_pid(tmp_path: Path) -> None:
    manager = CgroupManager(tmp_path)
    with pytest.raises(ValueError):
        manager.create(0)
    with pytest.raises(ValueError):
        manager.place_pid(0, 1)


def test_remove_refuses_nonempty_cgroup(tmp_path: Path) -> None:
    manager = CgroupManager(tmp_path)
    path = manager.create(1)
    (path / "child").mkdir()
    with pytest.raises(CgroupError):
        manager.remove(1)
