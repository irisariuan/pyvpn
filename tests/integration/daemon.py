"""Run ``pyvpn-daemon`` inside the test bed (PLAN.md §8).

The daemon is started in the "host" namespace through ``nsenter --net`` so it
keeps the mount namespace (and with it ``/sys/fs/cgroup``), exactly like the
CLI invocations the tests make. Everything lives under the test's tmp dir
except ``pyvpn.slice``, which is global; the harness removes it before and
after each test.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.integration.netbed import (
    ROOT,
    SERVICE_ADDRESS,
    TCP_PORT,
    UDP_PORT,
    VPN_IFACE,
    VPN_NETWORK,
    Netbed,
    NetbedError,
)

CGROUP_FS = Path("/sys/fs/cgroup")
CGROUP_SLICE = CGROUP_FS / "pyvpn.slice"
CLI = "from pyvpn.cli import main; raise SystemExit(main())"
POLICY = "vpn"


def config(*, on_down: str = "block") -> dict[str, Any]:
    """A destination-only-free policy that sends one app through vpn0."""
    return {
        "version": 1,
        "targets": [
            {
                "name": POLICY,
                "interface": VPN_IFACE,
                "gateway": f"{VPN_NETWORK}.1",
            }
        ],
        "policies": [
            {
                "name": POLICY,
                "targets": [POLICY],
                "on_down": on_down,
                "apps": [{"name": "pyvpn-probe-never-matches"}],
                "leak": {"dns_via_target": False},
            }
        ],
    }


@dataclass
class Daemon:
    """A running daemon and the paths its API and logs use."""

    bed: Netbed
    socket: Path
    log_path: Path
    process: subprocess.Popen[str]

    def status(self) -> dict[str, Any]:
        result = self.bed.run(
            [sys.executable, "-c", CLI, "--json", "--socket", str(self.socket), "status"],
            ns=self.bed.host,
            check=False,
            timeout=15,
            cwd=ROOT,
        )
        if result.returncode != 0:
            raise NetbedError(f"status failed: {result.stderr.strip() or result.stdout.strip()}")
        return json.loads(result.stdout)

    def wait_route(self, policy_id: int, route: str, *, timeout: float = 10.0) -> dict[str, Any]:
        """Wait until the daemon reports ``route`` for ``policy_id``."""
        deadline = time.monotonic() + timeout
        last: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise NetbedError(
                    f"daemon exited with {self.process.returncode}: {self.log_tail()}"
                )
            try:
                last = self.status()
            except (NetbedError, json.JSONDecodeError):
                time.sleep(0.1)
                continue
            for entry in last.get("policies", []):
                if entry.get("id") == policy_id and entry.get("route") == route:
                    return last
            time.sleep(0.1)
        raise NetbedError(
            f"policy {policy_id} never reached {route!r}: {last}; daemon log:\n{self.log_tail()}"
        )

    def probe(self, kind: str, *, timeout: float = 3.0) -> str:
        """Run the probe in the policy's cgroup and return the server-seen peer."""
        port = TCP_PORT if kind == "tcp" else UDP_PORT
        command = [
            sys.executable,
            "-m",
            "tests.integration.services",
            "probe",
            kind,
            SERVICE_ADDRESS,
            str(port),
            str(timeout),
        ]
        result = self.bed.run(
            [
                sys.executable,
                "-c",
                CLI,
                "--socket",
                str(self.socket),
                "run",
                "-p",
                POLICY,
                "--",
                *command,
            ],
            ns=self.bed.host,
            check=False,
            timeout=timeout + 15,
            cwd=ROOT,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise NetbedError(f"{kind} probe in policy {POLICY!r} failed: {detail}")
        return result.stdout.strip()

    def log_tail(self, lines: int = 25) -> str:
        text = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(text[-lines:])


def _clear_slice() -> None:
    """Remove ``pyvpn.slice``; fail loudly if a process still holds it."""
    for _ in range(100):
        if not CGROUP_SLICE.exists():
            return
        try:
            shutil.rmtree(CGROUP_SLICE)
            return
        except OSError:
            time.sleep(0.05)
    if CGROUP_SLICE.exists():
        raise NetbedError(f"cannot remove {CGROUP_SLICE}; a process may still be attached")


@contextlib.contextmanager
def daemon(
    bed: Netbed,
    tmp_path: Path,
    *,
    on_down: str = "block",
) -> Iterator[Daemon]:
    """Start the daemon in ``bed.host`` and stop it on exit."""
    if not (CGROUP_FS / "cgroup.controllers").exists() or not os.access(CGROUP_FS, os.W_OK):
        pytest.skip("needs a writable cgroup v2 tree at /sys/fs/cgroup")
    _clear_slice()

    work = tmp_path / "daemon"
    state = work / "state"
    state.mkdir(parents=True)
    config_path = work / "config.json"
    config_path.write_text(json.dumps(config(on_down=on_down)), encoding="utf-8")
    socket_path = work / "pyvpn.sock"
    log_path = work / "daemon.log"

    with log_path.open("w", encoding="utf-8") as log:
        process = bed.spawn(
            [
                sys.executable,
                "-m",
                "pyvpn.daemon.main",
                "--config",
                str(config_path),
                "--socket",
                str(socket_path),
                "--state-dir",
                str(state),
                "--no-process-watcher",
                "--log-level",
                "INFO",
            ],
            ns=bed.host,
            stdout=log,
            stderr=subprocess.STDOUT,
            cwd=ROOT,
        )
        running = Daemon(bed, socket_path, log_path, process)
        try:
            deadline = time.monotonic() + 15.0
            while not socket_path.exists():
                if process.poll() is not None:
                    raise NetbedError(
                        f"daemon exited with {process.returncode}: {running.log_tail()}"
                    )
                if time.monotonic() > deadline:
                    raise NetbedError(f"daemon did not open its socket: {running.log_tail()}")
                time.sleep(0.05)
            yield running
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    _clear_slice()
