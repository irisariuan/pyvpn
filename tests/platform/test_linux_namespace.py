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
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
CGROUP_FS = Path("/sys/fs/cgroup")
REMOTE = "203.0.113.9"  # off-link: only the default routes reach it
DNS_REMOTE = "198.51.100.53"
PORT = 9999


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
    ns = f"pyvpn-c-{tag}"
    cgroup = f"pyvpn-it-{tag}.slice"
    _run("ip", "netns", "add", ns)
    try:
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
        ):
            _run("ip", "-n", ns, *args)
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
        _run("ip", "netns", "delete", ns)
        if (CGROUP_FS / cgroup).exists():
            (CGROUP_FS / cgroup).rmdir()


# --- worker (runs inside the namespace) -------------------------------------------

_COUNTERS = {
    "wan_data": 'oifname "wan0" udp dport 9999',
    "target_data": 'oifname "d0" udp dport 9999',
    "wan_dns": 'oifname "wan0" udp dport 53',
    "target_dns": 'oifname "d0" udp dport 53',
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
if mark:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
try:
    s.sendto(b"pyvpn", (addr, port))
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
    from pyvpn.platform.linux.backend import LinuxBackend
    from pyvpn.state import AppBinding, PolicyPlan, RoutingPlan
    from tests.netfilter.test_ruleset import VARIANTS

    _install_counters()
    backend = LinuxBackend()
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

    # teardown -> nothing pyvpn owns is left.
    await backend.teardown()
    tables, rules, routes = _pyvpn_state()
    assert "pyvpn " not in tables.replace("pyvpntest", ""), tables
    assert "5201" not in rules, rules
    assert "table 1001" not in routes, routes
    before = _counters()
    _send(cgroup)
    assert _delta(before) == {"wan_data": 1}, _delta(before)

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
