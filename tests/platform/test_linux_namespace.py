"""LinuxBackend against the real kernel, inside a throwaway network namespace.

Run as root on Linux (PLAN.md §8)::

    sudo .venv/bin/python -m pytest -m integration tests/platform/test_linux_namespace.py

The test creates a network namespace and one cgroup (both uniquely named and
removed afterwards) and runs the scenarios in a worker process entered into
that namespace with ``nsenter --net``; ``ip netns exec`` would remount
``/sys`` and hide the cgroup tree that ``socket cgroupv2`` rules resolve.
Both "interfaces" are dummies; nft counters on postrouting show which one
traffic left through.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import uuid
from dataclasses import replace
from ipaddress import IPv4Network, ip_address
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
CGROUP_FS = Path("/sys/fs/cgroup")
REMOTE = "203.0.113.9"  # off-link: only the default routes reach it
DNS_REMOTE = "198.51.100.53"
PORT = 9999
VETH_LOCAL, VETH_PEER = "198.18.0.1", "198.18.0.2"  # not in the LAN exemption


def _run(*args: str, input: str | None = None) -> str:
    return subprocess.run(
        list(args), check=True, capture_output=True, text=True, timeout=20, input=input
    ).stdout


def test_linux_backend_in_namespace() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.skip("requires root in a disposable Linux test environment")
    for tool in ("ip", "nft", "nsenter"):
        if shutil.which(tool) is None:
            pytest.skip(f"requires {tool}")
    if not (CGROUP_FS / "cgroup.controllers").exists():
        pytest.skip("requires cgroup v2 at /sys/fs/cgroup")

    tag = uuid.uuid4().hex[:8]
    ns, peer = f"pyvpn-c-{tag}", f"pyvpn-p-{tag}"
    cgroup = f"pyvpn-it-{tag}.slice"
    echo: subprocess.Popen[bytes] | None = None
    _run("ip", "netns", "add", ns)
    try:
        _run("ip", "netns", "add", peer)
        (CGROUP_FS / cgroup).mkdir()
        for args in (
            ("link", "set", "lo", "up"),
            ("link", "add", "wan0", "type", "dummy"),
            ("addr", "add", "198.51.100.1/24", "dev", "wan0"),
            ("link", "set", "wan0", "up"),
            ("route", "add", "default", "dev", "wan0"),
            ("link", "add", "d0", "type", "dummy"),
            ("addr", "add", "192.0.2.1/24", "dev", "d0"),
            ("link", "set", "d0", "up"),
            # A real target for reply traffic: veth to a peer that echoes.
            ("link", "add", "v0", "type", "veth", "peer", "name", "e0", "netns", peer),
            ("addr", "add", f"{VETH_LOCAL}/30", "dev", "v0"),
            ("link", "set", "v0", "up"),
        ):
            _run("ip", "-n", ns, *args)
        for args in (
            ("link", "set", "lo", "up"),
            ("addr", "add", f"{REMOTE}/32", "dev", "lo"),
            ("addr", "add", f"{VETH_PEER}/30", "dev", "e0"),
            ("link", "set", "e0", "up"),
        ):
            _run("ip", "-n", peer, *args)
        echo = subprocess.Popen(
            ["nsenter", f"--net=/run/netns/{peer}", sys.executable, "-c", _ECHO, REMOTE]
        )
        env = {**os.environ, "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}", "PYTHONDONTWRITEBYTECODE": "1"}
        result = subprocess.run(
            ["nsenter", f"--net=/run/netns/{ns}", sys.executable, "-m", __spec__.name, cgroup],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    finally:
        if echo is not None:
            echo.kill()
            echo.wait()
        for name in (ns, peer):
            subprocess.run(["ip", "netns", "delete", name], capture_output=True, timeout=20)
        if (CGROUP_FS / cgroup).exists():
            (CGROUP_FS / cgroup).rmdir()


_ECHO = """
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 7777))
while True:
    data, addr = s.recvfrom(64)
    s.sendto(data, addr)
"""


# --- worker (runs inside the namespace) -------------------------------------------

_COUNTERS = {
    "wan_data": 'oifname "wan0" udp dport 9999',
    "target_data": 'oifname "d0" udp dport 9999',
    "wan_dns": 'oifname "wan0" udp dport 53',
    "target_dns": 'oifname "d0" udp dport 53',
    "wan_wg": 'oifname "wan0" udp dport 51820',
    "target_wg": 'oifname "d0" udp dport 51820',
}


def _counters() -> dict[str, int]:
    doc = json.loads(_run("nft", "-j", "list", "counters", "table", "inet", "pyvpntest"))
    return {
        item["counter"]["name"]: item["counter"]["packets"]
        for item in doc["nftables"]
        if "counter" in item
    }


def _install_counters() -> None:
    lines = ["add table inet pyvpntest"]
    lines.append("add chain inet pyvpntest post { type filter hook postrouting priority 200; }")
    for name, match in _COUNTERS.items():
        lines.append(f"add counter inet pyvpntest {name}")
        lines.append(f'add rule inet pyvpntest post {match} counter name "{name}"')
    _run("nft", "-f", "-", input="\n".join(lines) + "\n")


_CHILD = """
import os, socket, sys
cgroup, addr, port, mark = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
if cgroup:
    with open(f"/sys/fs/cgroup/{cgroup}/cgroup.procs", "w") as f:
        f.write(str(os.getpid()))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
if mark:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
try:
    s.sendto(b"pyvpn", (addr, port))
    if port == 7777:
        print("reply" if s.recvfrom(64)[0] == b"pyvpn" else "garbage")
except OSError as e:
    print("send failed:", e)
"""


def _send(cgroup: str | None, addr: str = REMOTE, port: int = PORT, mark: int = 0) -> str:
    return _run(sys.executable, "-c", _CHILD, cgroup or "", addr, str(port), str(mark))


def _delta(before: dict[str, int]) -> dict[str, int]:
    after = _counters()
    return {k: after[k] - before.get(k, 0) for k in after if after[k] != before.get(k, 0)}


def _pyvpn_state() -> tuple[str, str, str]:
    tables = _run("nft", "list", "tables")
    rules = _run("ip", "rule") + _run("ip", "-6", "rule")
    routes = _run("ip", "route", "show", "table", "all") + _run(
        "ip", "-6", "route", "show", "table", "all"
    )
    return tables, rules, routes


async def _worker(cgroup: str) -> None:
    from pyvpn.config.models import LeakSettings
    from pyvpn.constants import dns_stub_port, policy_mark, policy_rule_pref, policy_table
    from pyvpn.platform.linux.backend import LinuxBackend, NftError, run_nft
    from pyvpn.state import AppBinding, DestSet, PolicyPlan, RoutingPlan
    from tests.netfilter.test_ruleset import VARIANTS

    _install_counters()
    fail_commit = False

    async def commit_with_probe(script: str) -> None:
        if fail_commit and script.startswith("add table inet pyvpn\n"):
            # The new plan removed all routes, but the previous classifier is
            # still installed. Only the unmarked process may reach wan0.
            before = _counters()
            _send(cgroup)
            _send(None)
            delta = _delta(before)
            assert delta == {"wan_data": 1}, delta
            raise NftError("simulated commit failure")
        await run_nft(script)

    backend = LinuxBackend(nft=commit_with_probe)
    active = PolicyPlan(
        policy_id=1,
        mark=policy_mark(1),
        table=policy_table(1),
        rule_pref=policy_rule_pref(1),
        route="dev",
        interface="d0",
        gateway=None,
        apps=AppBinding(1, cgroup_paths=(cgroup,)),
        dests=None,
        leak=LeakSettings(),
        dns_stub_port=dns_stub_port(1),
    )

    # apply -> table, rules and routes present; a second apply is a no-op.
    await backend.apply(RoutingPlan((active,)))
    await backend.apply(RoutingPlan((active,)))
    tables, rules, routes = _pyvpn_state()
    assert "table inet pyvpn" in tables, tables
    assert "pyvpn_guard" not in tables, tables
    assert rules.count("5201:\tfrom all fwmark 0x50590001/0xffff007f lookup 1001") == 2, rules
    assert "default dev d0 table 1001 proto static metric 100" in routes, routes
    assert "unreachable default table 1001 proto static metric 32760" in routes, routes
    chains = _run("nft", "list", "table", "inet", "pyvpn")
    assert f'socket cgroupv2 level 1 "{cgroup}" jump p1' in chains, chains

    # The policy's process leaves via the target, every other process via wan0.
    before = _counters()
    _send(cgroup)
    _send(None)
    assert _delta(before) == {"target_data": 1, "wan_data": 1}, _delta(before)

    fail_commit = True
    with pytest.raises(NftError, match="simulated commit failure"):
        await backend.apply(RoutingPlan())
    fail_commit = False
    before = _counters()
    _send(cgroup)
    assert _delta(before) == {"target_data": 1}, _delta(before)

    # Port 53 from the policy's process goes to the stub on 127.0.0.1:5301...
    stub = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stub.bind(("127.0.0.1", dns_stub_port(1)))
    stub.settimeout(5)
    before = _counters()
    _send(cgroup, DNS_REMOTE, 53)
    assert stub.recvfrom(64)[0] == b"pyvpn"
    # ...but a socket that already carries the policy mark (the stub's own
    # upstream) is not redirected, and leaves via the target.
    _send(cgroup, DNS_REMOTE, 53, mark=policy_mark(1))
    assert _delta(before) == {"target_dns": 1}, _delta(before)
    stub.close()

    # Target link lost before the daemon reacts: the guard route holds.
    _run("ip", "link", "set", "d0", "down")
    before = _counters()
    _send(cgroup)
    assert _delta(before) == {}, _delta(before)

    # on_down: block -> kill switch plan: still nothing leaves anywhere.
    await backend.apply(RoutingPlan((replace(active, route="unreachable", interface=None),)))
    _, _, routes = _pyvpn_state()
    assert "default dev d0 table 1001" not in routes, routes
    before = _counters()
    _send(cgroup)
    _send(cgroup, DNS_REMOTE, 53, mark=policy_mark(1))
    assert _delta(before) == {}, _delta(before)
    _run("ip", "link", "set", "d0", "up")

    # A cgroup removed and created again gets a new id; the backend notices
    # and re-applies, so its processes are matched again.
    await backend.apply(RoutingPlan((active,)))
    (CGROUP_FS / cgroup).rmdir()
    (CGROUP_FS / cgroup).mkdir()
    await asyncio.sleep(2)  # the watcher polls every 0.5 s
    before = _counters()
    _send(cgroup)
    assert _delta(before) == {"target_data": 1}, _delta(before)

    # Strict rp_filter: replies through the target pass only because the
    # restored mark is used for validation (src_valid_mark, set by apply).
    veth = replace(active, interface="v0", gateway=ip_address(VETH_PEER))
    for knob in ("all", "v0"):
        _run("sysctl", "-q", f"net.ipv4.conf.{knob}.rp_filter=1")
    await backend.apply(RoutingPlan((veth,)))
    assert _run("sysctl", "-n", "net.ipv4.conf.all.src_valid_mark").strip() == "1"
    assert _send(cgroup, REMOTE, 7777).strip() == "reply"
    _run("sysctl", "-q", "net.ipv4.conf.all.src_valid_mark=0")  # control
    assert "timed out" in _send(cgroup, REMOTE, 7777)
    await backend.apply(RoutingPlan((veth,)))
    assert _send(cgroup, REMOTE, 7777).strip() == "reply"
    _run("sysctl", "-q", "net.ipv4.conf.all.rp_filter=0")

    # teardown -> nothing pyvpn owns is left.
    await backend.teardown()
    tables, rules, routes = _pyvpn_state()
    assert "pyvpn " not in tables.replace("pyvpntest", ""), tables
    assert "pyvpn_guard" not in tables, tables
    assert "5201" not in rules, rules
    assert "table 1001" not in routes, routes
    before = _counters()
    _send(cgroup)
    assert _delta(before) == {"wan_data": 1}, _delta(before)

    # A destination policy for every process must not catch the kernel
    # tunnel's own packets to an endpoint inside its destination set.
    if shutil.which("wg"):
        key = _run("wg", "genkey").strip()
        peer_key = _run("wg", "pubkey", input=_run("wg", "genkey")).strip()
        Path("/run/pyvpn-it-wg.key").write_text(key + "\n")
        try:
            _run("ip", "link", "add", "wg0", "type", "wireguard")
            _run(
                "wg",
                "set",
                "wg0",
                "private-key",
                "/run/pyvpn-it-wg.key",
                "peer",
                peer_key,
                "endpoint",
                f"{REMOTE}:51820",
                "allowed-ips",
                "10.99.0.2/32",
            )
        finally:
            Path("/run/pyvpn-it-wg.key").unlink()
        _run("ip", "addr", "add", "10.99.0.1/24", "dev", "wg0")
        _run("ip", "link", "set", "wg0", "up")
        everyone = replace(
            active,
            apps=AppBinding(1, any_process=True),
            dests=DestSet(1, frozenset({IPv4Network(f"{REMOTE}/32")})),
            dns_stub_port=None,
        )
        await backend.apply(RoutingPlan((everyone,)))
        before = _counters()
        _send(None)  # a user process to the destination: via the target
        _send(None, "10.99.0.2", 9)  # makes wg0 send a handshake to the endpoint
        await asyncio.sleep(1)
        delta = _delta(before)
        assert delta.get("target_data") == 1 and "target_wg" not in delta, delta
        assert delta.get("wan_wg", 0) >= 1, delta
        await backend.teardown()
        _run("ip", "link", "delete", "wg0")
    else:
        print("wg not installed; skipped the WireGuard endpoint check")

    # Every golden variant loads into the kernel and tears down cleanly.
    for name, plan in sorted(VARIANTS.items()):
        policies = []
        for p in plan.policies:
            apps = replace(p.apps, cgroup_paths=tuple(cgroup for _ in p.apps.cgroup_paths[:1]))
            iface = "d0" if p.route == "dev" else None
            policies.append(replace(p, apps=apps, interface=iface, gateway=None))
        try:
            await backend.apply(RoutingPlan(tuple(policies)))
        except Exception as e:
            raise AssertionError(f"variant {name} failed to apply: {e}") from e
    await backend.teardown()
    tables, rules, routes = _pyvpn_state()
    assert "5201" not in rules and "table 100" not in routes, (rules, routes)
    print("namespace scenarios passed")


if __name__ == "__main__":
    asyncio.run(_worker(sys.argv[1]))
