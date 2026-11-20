from __future__ import annotations

from pathlib import Path

import pytest

from pyvpn.apps.watcher import ProcessWatcher
from pyvpn.config.models import AppSelector, Policy


@pytest.mark.asyncio
async def test_startup_scan_places_matching_processes(tmp_path: Path) -> None:
    proc = tmp_path / "42"
    proc.mkdir()
    exe = tmp_path / "worker"
    exe.write_text("x")
    (proc / "exe").symlink_to(exe)
    (proc / "comm").write_text("worker\n")
    (proc / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
    (proc / "cgroup").write_text("0::/user.slice\n")
    placed: list[tuple[int, int]] = []

    async def place(pid: int, policy_id: int) -> None:
        placed.append((pid, policy_id))

    policy = Policy(name="p", targets=("t",), apps=(AppSelector(name="worker"),))
    watcher = ProcessWatcher([policy], place, proc_root=tmp_path)
    assert await watcher.scan() == 1
    assert placed == [(42, 1)]
    assert await watcher.handle_exec(42) == 1
    assert placed == [(42, 1)]
