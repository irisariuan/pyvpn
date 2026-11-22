"""``isolation: netns`` against the real kernel, inside the test bed (PLAN.md §3.6, §8).

Run as root on Linux::

    sudo .venv/bin/python -m pytest -m integration tests/platform/test_netns_namespace.py

The test bed's "host" namespace plays the machine under test: a worker
entered into it with ``nsenter --net`` drives ``LinuxBackend``, which creates
the policy namespace (a uniquely named ``pyvpn-tb-<tag>-p1``) and its veth.
Probes run inside the policy namespace; the internet-side echo server reports
the source address it saw (``198.51.100.2``: VPN link, ``192.0.2.2``: WAN).
Everything is removed afterwards, including the policy namespace.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from ipaddress import ip_address
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from tests.integration.netbed import Netbed

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
CGROUP_FS = Path("/sys/fs/cgroup")
VPN_SOURCE, WAN_SOURCE = "198.51.100.2", "192.0.2.2"


def test_netns_isolation_in_test_bed(netbed: Netbed) -> None:
    for tool in ("nft", "nsenter", "sysctl"):
        if shutil.which(tool) is None:
            pytest.skip(f"requires {tool}")
    if not (CGROUP_FS / "cgroup.controllers").exists():
        pytest.skip("requires cgroup v2 at /sys/fs/cgroup")
    prefix = f"pyvpn-tb-{netbed.tag}-p"
    made_slice = not (CGROUP_FS / "pyvpn.slice").exists()
    made_cgroup = not (CGROUP_FS / "pyvpn.slice/p-1").exists()
    try:
        with netbed.services():
            env = {
                **os.environ,
                "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            result = subprocess.run(
                [
                    "nsenter",
                    f"--net=/run/netns/{netbed.host}",
                    sys.executable,
                    "-m",
                    __spec__.name,
                    prefix,
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert "netns scenarios passed" in result.stdout, result.stdout
    finally:
        for name in netbed.namespaces():
            if name.startswith(prefix):
                subprocess.run(["ip", "netns", "delete", name], capture_output=True, timeout=20)
        if made_cgroup and (CGROUP_FS / "pyvpn.slice/p-1").exists():
            (CGROUP_FS / "pyvpn.slice/p-1").rmdir()
        if made_slice and (CGROUP_FS / "pyvpn.slice").exists():
            (CGROUP_FS / "pyvpn.slice").rmdir()


def test_pyvpn_run_isolated_end_to_end(netbed: Netbed) -> None:
    """The real daemon in the test bed; ``pyvpn run`` as an unprivileged user."""
    for tool in ("nft", "nsenter", "setpriv"):
        if shutil.which(tool) is None:
            pytest.skip(f"requires {tool}")
    if not (CGROUP_FS / "cgroup.controllers").exists():
        pytest.skip("requires cgroup v2 at /sys/fs/cgroup")
    prefix = f"pyvpn-tb-{netbed.tag}-p"
    made_slice = not (CGROUP_FS / "pyvpn.slice").exists()
    made_cgroup = not (CGROUP_FS / "pyvpn.slice/p-1").exists()
    work = Path(tempfile.mkdtemp(prefix="pyvpn-netns-e2e-"))
    work.chmod(0o755)
    sock = work / "pyvpn.sock"
    config = work / "config.json"
    config.write_text(
        json.dumps(
            {
                "version": 1,
                "targets": [{"name": "vpn", "interface": "vpn0", "gateway": "198.51.100.1"}],
                "policies": [
                    {
                        "name": "Torrents",
                        "targets": ["vpn"],
                        "on_down": "block",
                        "isolation": "netns",
                        "apps": [{"name": "pyvpn-it-none"}],
                    }
                ],
            }
        )
    )
    config.chmod(0o644)
    env = {**os.environ, "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}", "PYTHONDONTWRITEBYTECODE": "1"}
    daemon = subprocess.Popen(
        [
            "nsenter",
            f"--net=/run/netns/{netbed.host}",
            sys.executable,
            "-m",
            __spec__.name,
            "daemon",
            prefix,
            str(config),
            str(sock),
            str(work / "state"),
            str(work / "run"),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    nobody = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"]
    cli = [sys.executable, "-m", "pyvpn", "run", "--socket", str(sock), "-p", "Torrents"]
    try:
        with netbed.services():
            deadline = time.monotonic() + 20
            while not _isolated_ready(sock):
                if daemon.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError("the daemon did not install the namespace")
                time.sleep(0.2)

            from tests.integration.netbed import SERVICE_ADDRESS, TCP_PORT

            probe = [
                "--",
                sys.executable,
                "-m",
                "tests.integration.services",
                "probe",
                "tcp",
                SERVICE_ADDRESS,
                str(TCP_PORT),
                "2",
            ]
            out = ""
            for _ in range(3):
                result = subprocess.run(
                    [*nobody, *cli, *probe],
                    capture_output=True,
                    text=True,
                    env=env,
                    cwd=ROOT,
                    timeout=30,
                )
                out = result.stdout + result.stderr
                if result.returncode == 0:
                    break
            assert result.returncode == 0, out
            assert result.stdout.strip() == VPN_SOURCE, out

            # The command runs as the caller, inside the namespace, and its
            # exit status comes back through ``pyvpn run``.
            ident = subprocess.run(
                [*nobody, *cli, "--", "sh", "-c", "id -u; readlink /proc/self/ns/net; exit 7"],
                capture_output=True,
                text=True,
                env=env,
                cwd="/tmp",
                timeout=30,
            )
            assert ident.returncode == 7, ident.stdout + ident.stderr
            uid, ns = ident.stdout.split()
            assert uid == "65534"
            assert ns == f"net:[{os.stat(f'/run/netns/{prefix}1').st_ino}]"

            # Signals reach the command: SIGTERM to ``pyvpn run`` ends it.
            sleeper = subprocess.Popen([*nobody, *cli, "--", "sleep", "30"], env=env, cwd="/tmp")
            time.sleep(1.5)
            sleeper.terminate()
            assert sleeper.wait(timeout=10) == 128 + 15

            # A process outside the namespace cannot use place_pid for it.
            refused = subprocess.run(
                [*nobody, *cli, "--isolation", "none", "--", "true"],
                capture_output=True,
                text=True,
                env=env,
                cwd="/tmp",
                timeout=30,
            )
            assert refused.returncode == 1 and "isolation 'netns'" in refused.stderr, refused
    finally:
        daemon.terminate()
        try:
            out, _ = daemon.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            daemon.kill()
            out, _ = daemon.communicate()
        teardown = subprocess.run(
            [
                "nsenter",
                f"--net=/run/netns/{netbed.host}",
                sys.executable,
                "-m",
                __spec__.name,
                "teardown",
                prefix,
                str(work / "run"),
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        for name in netbed.namespaces():
            if name.startswith(prefix):
                subprocess.run(["ip", "netns", "delete", name], capture_output=True, timeout=20)
        shutil.rmtree(work, ignore_errors=True)
        if made_cgroup and (CGROUP_FS / "pyvpn.slice/p-1").exists():
            with contextlib.suppress(OSError):
                (CGROUP_FS / "pyvpn.slice/p-1").rmdir()
        if made_slice and (CGROUP_FS / "pyvpn.slice").exists():
            with contextlib.suppress(OSError):
                (CGROUP_FS / "pyvpn.slice").rmdir()
    assert teardown.returncode == 0, teardown.stdout + teardown.stderr


def _isolated_ready(sock: Path) -> bool:
    from pyvpn.apps.launcher import DaemonUnavailable, _Connection

    try:
        conn = _Connection(sock, 2.0)
    except DaemonUnavailable:
        return False
    try:
        status = conn.request("status", {})
    except DaemonUnavailable:
        return False
    finally:
        conn.close()
    return any(p["route"] == "dev" and p["isolation"] == "netns" for p in status["policies"])


async def _run_daemon(prefix: str, config: str, sock: str, state: str, run: str) -> int:
    from pyvpn.daemon.main import Options, build_daemon, serve
    from pyvpn.platform.linux.backend import LinuxBackend
    from pyvpn.platform.linux.netns import NetnsManager

    options = Options(
        config_path=Path(config),
        socket_path=Path(sock),
        state_dir=Path(state),
        process_watcher=False,
    )
    backend = LinuxBackend(netns=NetnsManager(prefix=prefix, run_dir=Path(run)))
    assembly = build_daemon(options, backend=backend)
    assembly.daemon.server._mode = 0o666
    return await serve(assembly)


async def _teardown(prefix: str, run: str) -> None:
    from pyvpn.platform.linux.backend import LinuxBackend
    from pyvpn.platform.linux.netns import NetnsManager

    await LinuxBackend(netns=NetnsManager(prefix=prefix, run_dir=Path(run))).teardown()


# --- worker (runs inside the test bed's host namespace) -------------------------------


def _run(*args: str, input: str | None = None, check: bool = True) -> str:
    result = subprocess.run(
        list(args), capture_output=True, text=True, timeout=30, input=input, check=False
    )
    if check and result.returncode:
        raise AssertionError(f"{' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def _in_policy(netns: str, *argv: str, timeout: float = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["nsenter", f"--net=/run/netns/{netns}", *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=ROOT,
    )


def _probe(netns: str, kind: str = "tcp", *, attempts: int = 1) -> str | None:
    """Source address the echo server saw, or None when nothing got through."""
    from tests.integration.netbed import SERVICE_ADDRESS, TCP_PORT, UDP_PORT

    port = TCP_PORT if kind == "tcp" else UDP_PORT
    for _ in range(attempts):
        result = _in_policy(
            netns,
            sys.executable,
            "-m",
            "tests.integration.services",
            "probe",
            kind,
            SERVICE_ADDRESS,
            str(port),
            "2",
        )
        if result.returncode == 0:
            return result.stdout.strip()
    return None


def _reaches(netns: str, kind: str = "tcp") -> str | None:
    """Like ``_probe``, but tolerate a slow first neighbour lookup."""
    return _probe(netns, kind, attempts=3)


_DNS_CLIENT = """
import socket, sys
server, proto = sys.argv[1], sys.argv[2]
if proto == "udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(b"query", (server, 53))
    print(s.recvfrom(512)[0].decode())
else:
    s = socket.create_connection((server, 53), timeout=3)
    s.sendall(b"query")
    s.shutdown(socket.SHUT_WR)
    print(s.recv(512).decode())
"""


async def _fake_stub(port: int) -> tuple[Any, Any]:
    """A stand-in for the policy's DNS stub on the host loopback: tags replies."""
    loop = asyncio.get_running_loop()

    class Udp(asyncio.DatagramProtocol):
        def connection_made(self, transport: Any) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, addr: Any) -> None:
            self.transport.sendto(b"stub-udp:" + data, addr)

    async def tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"stub-tcp:" + await reader.read(512))
        await writer.drain()
        writer.close()

    udp, _ = await loop.create_datagram_endpoint(Udp, local_addr=("127.0.0.1", port))
    server = await asyncio.start_server(tcp, "127.0.0.1", port)
    return udp, server


def _forwarding(iface: str) -> str:
    return Path(f"/proc/sys/net/ipv4/conf/{iface}/forwarding").read_text().strip()


async def _worker(prefix: str) -> None:
    from pyvpn.apps.cgroups import CgroupManager
    from pyvpn.config.models import LeakSettings
    from pyvpn.constants import (
        dns_stub_port,
        policy_cgroup,
        policy_mark,
        policy_rule_pref,
        policy_table,
    )
    from pyvpn.platform.base import IsolatedCommand
    from pyvpn.platform.linux.backend import LinuxBackend, NftError, run_nft
    from pyvpn.platform.linux.netns import NetnsManager
    from pyvpn.state import AppBinding, PolicyPlan, RoutingPlan
    from tests.integration.netbed import VPN_IFACE, VPN_NETWORK

    run_dir = Path(tempfile.mkdtemp(prefix="pyvpn-netns-it-"))
    cgroups = CgroupManager(CGROUP_FS)
    cgroups.create(1)
    netns = f"{prefix}1"
    fail_commit = False

    async def nft(script: str) -> None:
        if fail_commit and script.startswith("add table inet pyvpn\n"):
            raise NftError("simulated commit failure")
        await run_nft(script)

    def backend() -> LinuxBackend:
        return LinuxBackend(nft=nft, netns=NetnsManager(prefix=prefix, run_dir=run_dir))

    active = PolicyPlan(
        policy_id=1,
        mark=policy_mark(1),
        table=policy_table(1),
        rule_pref=policy_rule_pref(1),
        route="dev",
        interface=VPN_IFACE,
        gateway=ip_address(f"{VPN_NETWORK}.1"),
        apps=AppBinding(1, cgroup_paths=(policy_cgroup(1),)),
        dests=None,
        leak=LeakSettings(),
        dns_stub_port=dns_stub_port(1),
        isolation="netns",
    )
    blocked = replace(active, route="unreachable", interface=None, gateway=None)
    fallback = replace(active, route="main", interface=None, gateway=None)

    # A failed first commit leaves the new namespace cut off: nothing leaves.
    first = backend()
    fail_commit = True
    with pytest.raises(NftError):
        await first.apply(RoutingPlan((active,)))
    fail_commit = False
    assert Path(f"/run/netns/{netns}").exists()
    assert _forwarding("pyvpn-h1") == "0"
    assert _probe(netns) is None
    assert first._netns.ready(1) is None

    # Target up: everything from the namespace leaves through the VPN link.
    await first.apply(RoutingPlan((active,)))
    assert _reaches(netns) == VPN_SOURCE
    assert _reaches(netns, "udp") == VPN_SOURCE
    assert _forwarding(VPN_IFACE) == "1"
    rules = _run("ip", "-4", "rule")
    assert "iif pyvpn-h1 lookup 1001" in rules, rules
    # No IPv6 inside the namespace.
    v6 = _in_policy(netns, "ip", "-6", "addr")
    assert "inet6" not in v6.stdout, v6.stdout

    # DNS to any server, including a loopback resolver, reaches the stub.
    udp, server = await _fake_stub(dns_stub_port(1))
    try:
        for target in ("127.0.0.53", "192.0.2.1", "8.8.8.8"):
            for proto in ("udp", "tcp"):
                out = await asyncio.to_thread(
                    _in_policy, netns, sys.executable, "-c", _DNS_CLIENT, target, proto
                )
                assert out.stdout.strip() == f"stub-{proto}:query", (target, proto, out)
    finally:
        udp.close()
        server.close()

    # Kill switch: target down, nothing leaves -- not via the WAN either.
    await first.apply(RoutingPlan((blocked,)))
    assert _probe(netns) is None
    assert _probe(netns, "udp") is None
    # The WAN default route exists in the host namespace; the iif rule and
    # the unreachable table still win even with nft's forward chain gone.
    _run("nft", "delete", "chain", "inet", "pyvpn", "forward", check=False)
    _run("nft", "flush", "chain", "inet", "pyvpn", "forward", check=False)
    assert _probe(netns) is None
    await first.apply(RoutingPlan((blocked,)))  # restore the full ruleset

    # on_down: default and no usable target: the host's default route.
    await first.apply(RoutingPlan((fallback,)))
    assert _reaches(netns) == WAN_SOURCE
    assert "iif pyvpn-h1" not in _run("ip", "-4", "rule")

    # Back to the target; start a command as an unprivileged user in it.
    await first.apply(RoutingPlan((active,)))
    out_path = run_dir / "child.out"
    out_fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    saved = os.dup(1)
    os.dup2(out_fd, 1)
    try:
        pidfd = os.pidfd_open(os.getpid())
        child = await first.spawn_isolated(
            cgroups,
            IsolatedCommand(
                policy_id=1,
                argv=(
                    "sh",
                    "-c",
                    "id -u; id -g; readlink /proc/self/ns/net; cat /proc/self/cgroup; pwd",
                ),
                env={"PATH": "/usr/bin:/bin"},
                cwd="/tmp",
                umask=0o022,
                uid=65534,
                gid=65534,
                client_pid=os.getpid(),
                client_pidfd=pidfd,
            ),
            lambda: None,
        )
        code = await child.wait()
    finally:
        os.dup2(saved, 1)
        os.close(saved)
        os.close(out_fd)
    lines = out_path.read_text().split()
    netns_inode = os.stat(f"/run/netns/{netns}").st_ino
    assert code == 0, lines
    assert lines[:2] == ["65534", "65534"], lines
    assert lines[2] == f"net:[{netns_inode}]", lines
    assert lines[3] == "0::/pyvpn.slice/p-1", lines
    assert lines[4] == "/tmp", lines

    # Daemon restart: a new backend adopts the namespace without recreating it.
    await first.close()
    second = backend()
    await second.apply(RoutingPlan((active,)))
    assert os.stat(f"/run/netns/{netns}").st_ino == netns_inode
    assert _reaches(netns) == VPN_SOURCE
    await second.close()

    # Teardown from yet another instance: veth, rules and forwarding go; the
    # namespace stays (apps inside are cut off) until its policy is gone.
    third = backend()
    await third.teardown()
    assert "pyvpn-h1" not in {name for _, name in socket.if_nameindex()}
    assert "iif pyvpn-h1" not in _run("ip", "-4", "rule")
    assert _forwarding(VPN_IFACE) == "0"
    assert "table inet pyvpn\n" not in _run("nft", "list", "tables") + "\n"
    assert Path(f"/run/netns/{netns}").exists()
    assert _probe(netns) is None

    # A plan without the policy deletes its namespace.
    await third.apply(RoutingPlan((replace(active, isolation="none"),)))
    assert not Path(f"/run/netns/{netns}").exists()
    await third.teardown()
    shutil.rmtree(run_dir, ignore_errors=True)
    print("netns scenarios passed")


if __name__ == "__main__":
    if sys.argv[1] == "daemon":
        raise SystemExit(asyncio.run(_run_daemon(*sys.argv[2:7])))
    if sys.argv[1] == "teardown":
        asyncio.run(_teardown(sys.argv[2], sys.argv[3]))
    else:
        asyncio.run(_worker(sys.argv[1]))
