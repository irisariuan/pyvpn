from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from pyvpn.apps.cgroups import CgroupError
from pyvpn.apps.watcher import ProcessWatcher
from pyvpn.config.models import AppSelector, Policy

POLICY = Policy(name="p", targets=("t",), apps=(AppSelector(name="worker"),))


def fake_process(root: Path, pid: int, name: str = "worker", cgroup: str = "/user.slice") -> Path:
    proc = root / str(pid)
    proc.mkdir(exist_ok=True)
    exe = root / f"bin-{name}"
    exe.write_text("x")
    if (proc / "exe").is_symlink():
        (proc / "exe").unlink()
    (proc / "exe").symlink_to(exe)
    (proc / "comm").write_text(f"{name}\n")
    (proc / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
    (proc / "cgroup").write_text(f"0::{cgroup}\n")
    return proc


class Recorder:
    def __init__(self) -> None:
        self.placed: list[tuple[int, int]] = []

    async def __call__(self, pid: int, policy_id: int) -> None:
        self.placed.append((pid, policy_id))


async def test_startup_scan_places_matching_processes(tmp_path: Path) -> None:
    fake_process(tmp_path, 42)
    place = Recorder()
    watcher = ProcessWatcher([POLICY], place, proc_root=tmp_path)
    assert await watcher.scan() == 1
    assert place.placed == [(42, 1)]


async def test_process_already_in_policy_cgroup_is_not_moved(tmp_path: Path) -> None:
    fake_process(tmp_path, 42, cgroup="/pyvpn.slice/p-1")
    place = Recorder()
    watcher = ProcessWatcher([POLICY], place, proc_root=tmp_path)
    assert await watcher.handle_exec(42) == 1
    assert place.placed == []


async def test_reused_pid_is_placed_again(tmp_path: Path) -> None:
    proc = fake_process(tmp_path, 42)
    place = Recorder()
    watcher = ProcessWatcher([POLICY], place, proc_root=tmp_path)
    await watcher.handle_exec(42)
    (proc / "cgroup").write_text("0::/pyvpn.slice/p-1\n")
    await watcher.handle_exec(42)
    assert place.placed == [(42, 1)]
    # The process exits and the kernel hands PID 42 to a new matching process.
    fake_process(tmp_path, 42, cgroup="/user.slice")
    await watcher.handle_exec(42)
    assert place.placed == [(42, 1), (42, 1)]


async def test_exit_during_placement_does_not_stop_watching(tmp_path: Path) -> None:
    import shutil

    fake_process(tmp_path, 41)
    fake_process(tmp_path, 42)
    placed: list[int] = []

    async def place(pid: int, policy_id: int) -> None:
        if pid == 41:
            shutil.rmtree(tmp_path / "41")
            raise CgroupError("cannot place pid 41: No such process")
        placed.append(pid)

    async def events() -> AsyncIterator[int]:
        fake_process(tmp_path, 41)
        yield 41
        yield 42

    watcher = ProcessWatcher([POLICY], place, proc_root=tmp_path)
    await watcher.run(events())  # scan: 41 exits, 42 placed; then the events
    assert placed == [42, 42]


async def test_placement_failure_of_live_process_is_logged(tmp_path: Path, caplog) -> None:  # type: ignore[no-untyped-def]
    fake_process(tmp_path, 42)

    async def place(pid: int, policy_id: int) -> None:
        raise CgroupError("permission denied")

    watcher = ProcessWatcher([POLICY], place, proc_root=tmp_path)
    assert await watcher.scan() == 0
    assert "cannot place process 42" in caplog.text


async def test_event_queued_during_scan_is_handled(tmp_path: Path) -> None:
    place = Recorder()

    async def events() -> AsyncIterator[int]:
        # Stands in for a subscription opened before the scan: PID 43 started
        # after /proc was listed, so only the queued event reports it.
        yield 43

    watcher = ProcessWatcher([POLICY], place, proc_root=tmp_path)
    original_scan = watcher.scan

    async def scan_then_start() -> int:
        moved = await original_scan()
        fake_process(tmp_path, 43)
        return moved

    watcher.scan = scan_then_start  # type: ignore[method-assign]
    await watcher.run(events())
    assert place.placed == [(43, 1)]
