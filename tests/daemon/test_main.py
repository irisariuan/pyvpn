"""The composition root wires real parts; no root, no host network.

Interfaces come from a fake netlink source, cgroups live under ``tmp_path``,
DNS stubs are off (``dns_via_target: false``) and routing uses dry-run or
fakes, so nothing here touches the host's routing, nft, cgroups or ports.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
from collections.abc import AsyncIterator
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, ClassVar

import pytest

from pyvpn.config.models import Config
from pyvpn.constants import policy_cgroup
from pyvpn.daemon import main as daemon_main
from pyvpn.daemon.dryrun import DryRunBackend
from pyvpn.daemon.main import (
    LINUX_BACKEND_MODULE,
    Assembly,
    BackendUnavailable,
    Options,
    ProcessWatcherRunner,
    build_daemon,
    load_backend,
)
from pyvpn.daemon.server import PeerCred
from pyvpn.platform.linux.backend import LinuxBackend
from pyvpn.targets.watcher import InterfaceSnapshot
from tests.routing._fakes import FakeNetlink as FakeRouteNetlink


def write_config(path: Path, *, policies: list[dict[str, Any]] | None = None) -> Config:
    data = {
        "version": 1,
        "targets": [{"name": "jp", "interface": "wg-jp"}],
        "policies": policies
        or [
            {
                "name": "Japan",
                "targets": ["jp"],
                "on_down": "block",
                "apps": [{"name": "firefox"}],
                "leak": {"dns_via_target": False},
            }
        ],
    }
    path.write_text(json.dumps(data))
    return Config.model_validate(data)


class FakeNetlink:
    """Reports ``wg-jp`` up once, then stays quiet."""

    def __init__(self, *, up: bool = True) -> None:
        self.up = up

    async def events(self) -> AsyncIterator[tuple[InterfaceSnapshot, ...]]:
        yield (InterfaceSnapshot("wg-jp", 7, self.up, addresses=(IPv4Address("10.7.0.2"),)),)
        await asyncio.Event().wait()


def missing_linux_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    real = daemon_main.importlib.import_module

    def import_module(name: str, package: str | None = None) -> types.ModuleType:
        if name == LINUX_BACKEND_MODULE:
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return real(name, package)

    monkeypatch.setattr(daemon_main.importlib, "import_module", import_module)
    monkeypatch.delitem(sys.modules, LINUX_BACKEND_MODULE, raising=False)


def test_linux_backend_missing_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    missing_linux_backend(monkeypatch)
    with pytest.raises(BackendUnavailable, match="refusing to start"):
        load_backend("linux")


def test_main_exits_without_linux_backend(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    missing_linux_backend(monkeypatch)
    write_config(tmp_path / "config.json")
    code = daemon_main.main(["--config", str(tmp_path / "config.json")])
    assert code == 2
    assert "Linux routing backend is not part of this build" in capsys.readouterr().err


def test_linux_backend_is_loaded_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType(LINUX_BACKEND_MODULE)

    class LinuxBackend(DryRunBackend):
        pass

    module.LinuxBackend = LinuxBackend  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, LINUX_BACKEND_MODULE, module)
    assert isinstance(load_backend("linux"), LinuxBackend)


def test_dry_run_never_touches_system_cgroups(tmp_path: Path) -> None:
    options = Options(config_path=tmp_path / "c.json", state_dir=tmp_path, backend="dry-run")
    assert options.resolved_cgroup_root() == tmp_path / "cgroup-dry-run"
    assert not options.watch_processes()
    linux = Options(config_path=tmp_path / "c.json", state_dir=tmp_path)
    assert linux.resolved_cgroup_root() == Path("/sys/fs/cgroup")
    assert linux.watch_processes()


async def test_linux_placement_accepts_domain_only_policy_alongside_app_policy(
    tmp_path: Path,
) -> None:
    opts = Options(
        config_path=tmp_path / "config.json",
        socket_path=tmp_path / "p.sock",
        state_dir=tmp_path / "state",
        cgroup_root=tmp_path / "cgroups",
        process_watcher=False,
    )
    config = write_config(opts.config_path)
    domain_policy = config.policies[0].model_copy(
        update={"name": "Office", "apps": (), "domains": ("ip:203.0.113.9",)}
    )
    config = config.model_copy(update={"policies": (*config.policies, domain_policy)})
    scripts: list[str] = []

    async def nft(script: str) -> None:
        scripts.append(script)

    root = opts.resolved_cgroup_root()
    backend = LinuxBackend(
        nft=nft, netlink=FakeRouteNetlink([]), cgroup_root=root, proc_sys=tmp_path / "proc"
    )
    assembly = build_daemon(opts, backend=backend, config=config, netlink=FakeNetlink())
    # The daemon reloads configuration from disk during startup.
    opts.config_path.write_text(config.model_dump_json())
    await assembly.daemon.start()
    try:
        state = opts.state_dir / "state.json"
        assert "Office" not in state.read_text()  # reserve the slot only when a PID is placed
        assert any(
            f'check_cgroup socket cgroupv2 level 2 "{policy_cgroup(2)}" return' in script
            and "output meta skuid >= 0 jump p2" in script
            for script in scripts
        )
        procs = root / policy_cgroup(2) / "cgroup.procs"
        procs.touch()
        await assembly.daemon.handle(
            "place_pid", {"pid": 123, "policy": "Office"}, PeerCred(1, 0, 0)
        )
        assert procs.read_text() == "123\n"
        assert "Office" in state.read_text()
    finally:
        await assembly.daemon.stop()
        await assembly.close()
        await backend.teardown()


def build(tmp_path: Path, *, up: bool = True, **options: Any) -> Assembly:
    config = write_config(tmp_path / "config.json")
    opts = Options(
        config_path=tmp_path / "config.json",
        socket_path=tmp_path / "pyvpn.sock",
        state_dir=tmp_path / "state",
        backend="dry-run",
        **options,
    )
    return build_daemon(opts, backend=DryRunBackend(), config=config, netlink=FakeNetlink(up=up))


async def call(sock: Path, method: str) -> dict[str, Any]:
    reader, writer = await asyncio.open_unix_connection(str(sock))
    writer.write(json.dumps({"id": 1, "method": method, "params": {}}).encode() + b"\n")
    await writer.drain()
    response: dict[str, Any] = json.loads(await reader.readline())
    writer.close()
    await writer.wait_closed()
    return response


async def settle(backend: DryRunBackend, applies: int) -> None:
    for _ in range(200):
        if backend.applies >= applies:
            return
        await asyncio.sleep(0.01)


async def test_daemon_runs_end_to_end_on_real_parts(tmp_path: Path) -> None:
    assembly = build(tmp_path)
    backend = assembly.backend
    assert isinstance(backend, DryRunBackend)
    await assembly.daemon.start()
    try:
        await settle(backend, 2)  # startup apply, then the target update
        assert backend.installed is not None
        (policy,) = backend.installed.policies
        assert (policy.route, policy.interface, policy.target) == ("dev", "wg-jp", "jp")
        assert policy.apps.cgroup_paths == ("pyvpn.slice/p-1",)
        # AppManager made the policy cgroup under the scratch root, not /sys/fs/cgroup.
        assert (tmp_path / "state" / "cgroup-dry-run" / "pyvpn.slice" / "p-1").is_dir()

        status = await call(tmp_path / "pyvpn.sock", "status")
        assert status["ok"], status
        audit = await call(tmp_path / "pyvpn.sock", "audit")
        assert audit["ok"], audit
        assert audit["result"]["backend"] == "dry-run"
        assert "dry-run backend: no traffic is routed or blocked" in audit["result"]["warnings"]
        assert audit["result"]["dns"] == {"Japan": "No per-policy DNS stub configured"}
    finally:
        await assembly.daemon.stop()
        await assembly.close()


async def test_kill_switch_blocks_when_target_is_down(tmp_path: Path) -> None:
    assembly = build(tmp_path, up=False)
    backend = assembly.backend
    assert isinstance(backend, DryRunBackend)
    await assembly.daemon.start()
    try:
        await settle(backend, 1)
        assert backend.installed is not None
        assert backend.installed.policies[0].route == "unreachable"
    finally:
        await assembly.daemon.stop()
        await assembly.close()


class FakeProcessWatcher:
    instances: ClassVar[list[FakeProcessWatcher]] = []

    def __init__(self, policies: Any, place: Any, *, groups: Any = ()) -> None:
        self.names = [policy.name for policy in policies]
        self.stopped = False
        FakeProcessWatcher.instances.append(self)

    async def run_proc_connector(self) -> None:
        await asyncio.Event().wait()

    def stop(self) -> None:
        self.stopped = True


async def test_process_watcher_follows_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeProcessWatcher.instances = []
    monkeypatch.setattr(daemon_main, "ProcessWatcher", FakeProcessWatcher)
    assembly = build(tmp_path, process_watcher=True)
    assert isinstance(assembly.process_watcher, ProcessWatcherRunner)
    await assembly.daemon.start()
    try:
        assert [w.names for w in FakeProcessWatcher.instances] == [["Japan"]]
        write_config(
            tmp_path / "config.json",
            policies=[
                {
                    "name": "Japan",
                    "targets": ["jp"],
                    "apps": [{"name": "firefox"}, {"name": "steam"}],
                    "leak": {"dns_via_target": False},
                },
                {
                    "name": "Torrents",
                    "targets": ["jp"],
                    "on_down": "block",
                    "apps": [{"exe": "/usr/bin/qbittorrent"}],
                    "leak": {"dns_via_target": False},
                },
            ],
        )
        await assembly.daemon.reload()
        first, second = FakeProcessWatcher.instances
        assert first.stopped
        assert second.names == ["Japan", "Torrents"]
    finally:
        await assembly.daemon.stop()
        await assembly.close()
    assert FakeProcessWatcher.instances[-1].stopped


class FlakyBackend(DryRunBackend):
    """Fails the first ``fails`` applies, like a backend that is not ready yet."""

    def __init__(self, fails: int) -> None:
        super().__init__()
        self.fails = fails

    async def apply(self, plan: Any) -> None:
        if self.fails:
            self.fails -= 1
            raise RuntimeError("nft: not ready")
        await super().apply(plan)


async def test_watcher_placement_is_refused_until_rules_are_installed(tmp_path: Path) -> None:
    config = write_config(tmp_path / "config.json")
    opts = Options(
        config_path=tmp_path / "config.json",
        socket_path=tmp_path / "pyvpn.sock",
        state_dir=tmp_path / "state",
        backend="dry-run",
    )
    backend = FlakyBackend(fails=1_000)  # every apply fails during the test
    assembly = build_daemon(opts, backend=backend, config=config, netlink=FakeNetlink(up=False))
    daemon = assembly.daemon
    procs = tmp_path / "state" / "cgroup-dry-run" / "pyvpn.slice" / "p-1" / "cgroup.procs"
    await daemon.start()
    try:
        assert daemon.reconciler.applied is None
        with pytest.raises(daemon_main.ApiError, match="not installed"):
            await daemon.place_trusted(4242, 1)
        assert not procs.exists()
    finally:
        await daemon.stop()
        await assembly.close()


class PlacingWatcher:
    """Tries to place pid 4242 in policy 1 at start and on every scan."""

    instances: ClassVar[list[PlacingWatcher]] = []

    def __init__(self, policies: Any, place: Any, *, groups: Any = ()) -> None:
        self.place = place
        self.scans = 0
        PlacingWatcher.instances.append(self)

    async def run_proc_connector(self) -> None:
        await self.place(4242, 1)
        await asyncio.Event().wait()

    async def scan(self) -> int:
        self.scans += 1
        await self.place(4242, 1)
        return 1

    def stop(self) -> None:
        pass


async def test_deferred_processes_are_placed_once_rules_are_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    PlacingWatcher.instances = []
    monkeypatch.setattr(daemon_main, "ProcessWatcher", PlacingWatcher)
    config = write_config(tmp_path / "config.json")
    opts = Options(
        config_path=tmp_path / "config.json",
        socket_path=tmp_path / "pyvpn.sock",
        state_dir=tmp_path / "state",
        backend="dry-run",
        process_watcher=True,
    )
    backend = FlakyBackend(fails=1)  # startup apply fails, the target update succeeds
    assembly = build_daemon(opts, backend=backend, config=config, netlink=FakeNetlink())
    procs = tmp_path / "state" / "cgroup-dry-run" / "pyvpn.slice" / "p-1" / "cgroup.procs"
    await assembly.daemon.start()
    try:
        await settle(backend, 1)
        (watcher,) = PlacingWatcher.instances
        for _ in range(200):
            if watcher.scans:
                break
            await asyncio.sleep(0.01)
        assert watcher.scans == 1
        assert procs.read_text() == "4242\n"
    finally:
        await assembly.daemon.stop()
        await assembly.close()


def test_backend_dependency_errors_exit_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    def import_module(name: str, package: str | None = None) -> types.ModuleType:
        raise ModuleNotFoundError("No module named 'pyroute2'", name="pyroute2")

    monkeypatch.setattr(daemon_main.importlib, "import_module", import_module)
    with pytest.raises(BackendUnavailable, match="missing module 'pyroute2'"):
        load_backend("linux")


def test_process_watcher_is_rejected_with_dry_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_config(tmp_path / "config.json")
    argv = ["--backend", "dry-run", "--process-watcher", "--config", str(tmp_path / "config.json")]
    assert daemon_main.main(argv) == 2
    assert "cannot be used with --backend dry-run" in capsys.readouterr().err


async def test_unenforceable_exclusion_is_refused(tmp_path: Path) -> None:
    policy = {
        "name": "Corp",
        "targets": ["jp"],
        "domains": ["cidr:203.0.113.0/24"],
        "exclude_apps": [{"name": "openvpn"}],
        "leak": {"dns_via_target": False},
    }
    config = write_config(tmp_path / "config.json", policies=[policy])
    opts = Options(
        config_path=tmp_path / "config.json",
        socket_path=tmp_path / "pyvpn.sock",
        state_dir=tmp_path / "state",
        backend="dry-run",
    )
    backend = DryRunBackend()
    assembly = build_daemon(opts, backend=backend, config=config, netlink=FakeNetlink())
    try:
        with pytest.raises(daemon_main.ApiError, match="exclude_apps name: 'openvpn'"):
            await assembly.daemon.start()
        assert backend.applies == 0
    finally:
        await assembly.close()


async def test_netns_isolation_is_refused_by_the_dry_run_backend(tmp_path: Path) -> None:
    policy = {
        "name": "Strict",
        "targets": ["jp"],
        "on_down": "block",
        "apps": [{"name": "firefox"}],
        "isolation": "netns",
        "leak": {"dns_via_target": False},
    }
    config = write_config(tmp_path / "config.json", policies=[policy])
    opts = Options(
        config_path=tmp_path / "config.json",
        socket_path=tmp_path / "pyvpn.sock",
        state_dir=tmp_path / "state",
        backend="dry-run",
    )
    backend = DryRunBackend()
    assembly = build_daemon(opts, backend=backend, config=config, netlink=FakeNetlink())
    try:
        with pytest.raises(daemon_main.ApiError, match="isolation 'netns' is not supported"):
            await assembly.daemon.start()
        assert backend.applies == 0
    finally:
        await assembly.close()


class FailingWatcher:
    def __init__(self, policies: Any, place: Any, *, groups: Any = ()) -> None:
        pass

    async def run_proc_connector(self) -> None:
        raise PermissionError("proc connector needs CAP_NET_ADMIN")

    def stop(self) -> None:
        pass


async def test_process_watcher_failure_shows_in_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(daemon_main, "ProcessWatcher", FailingWatcher)
    assembly = build(tmp_path, process_watcher=True)
    await assembly.daemon.start()
    try:
        for _ in range(100):
            if assembly.daemon.status().last_error:
                break
            await asyncio.sleep(0.01)
        error = assembly.daemon.status().last_error
        assert error is not None
        assert "process watcher failed: proc connector needs CAP_NET_ADMIN" in error
    finally:
        await assembly.daemon.stop()
        await assembly.close()
