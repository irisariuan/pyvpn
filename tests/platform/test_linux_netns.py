"""Namespace manager, DNS relay and isolated launch with fakes (pure).

The kernel side is covered by ``tests/platform/test_netns_namespace.py``
(integration marker, root).
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from pyvpn.config.models import LeakSettings
from pyvpn.constants import (
    dns_stub_port,
    policy_cgroup,
    policy_mark,
    policy_rule_pref,
    policy_table,
)
from pyvpn.netfilter.render import render
from pyvpn.netfilter.ruleset import build_netns_ruleset
from pyvpn.platform.base import IsolatedCommand
from pyvpn.platform.linux.isolated import client_fd, spawn_isolated, supplementary_groups
from pyvpn.platform.linux.netns import DnsRelay, NetnsManager, veth_policy_id
from pyvpn.state import AppBinding, PolicyPlan, RoutingPlan

NETNS_DIR = Path("/run/netns")


def plan(pid: int = 1, **kw: Any) -> PolicyPlan:
    base: dict[str, Any] = {
        "policy_id": pid,
        "mark": policy_mark(pid),
        "table": policy_table(pid),
        "rule_pref": policy_rule_pref(pid),
        "route": "dev",
        "interface": "tun0",
        "gateway": None,
        "apps": AppBinding(pid, cgroup_paths=(policy_cgroup(pid),)),
        "dests": None,
        "leak": LeakSettings(),
        "dns_stub_port": None,
        "isolation": "netns",
    }
    base.update(kw)
    return PolicyPlan(**base)


class FakeSystem:
    """Records commands; keeps just enough state to answer the queries."""

    def __init__(self) -> None:
        self.log: list[str] = []
        self.namespaces: set[str] = set()
        self.link_set: set[str] = {"lo", "eth0", "tun0"}
        self.sysctl: dict[str, str] = {
            "net/ipv6/conf/all/disable_ipv6": "0",
            "net/ipv4/conf/tun0/forwarding": "0",
            "net/ipv4/conf/eth0/forwarding": "0",
        }
        self.rules: list[dict[str, Any]] = []
        self.default_routes: list[dict[str, Any]] = [{"dst": "default", "dev": "eth0"}]
        self.listeners: list[tuple[Path, int]] = []
        self.fail: str | None = None

    async def run(self, argv: Sequence[str], *, input: str | None = None) -> str:
        line = " ".join(argv)
        if self.fail is not None and line.startswith(self.fail):
            from pyvpn.platform.linux.netns import NetnsError

            raise NetnsError(f"{line}: simulated failure")
        if argv[:4] == ["ip", "-j", "-4", "rule"]:
            return json.dumps(self.rules)
        if argv[:4] == ["ip", "-j", "-4", "route"]:
            return json.dumps(self.default_routes)
        self.log.append(line + (" <<nft" if input is not None else ""))
        if argv[:3] == ["ip", "netns", "add"]:
            self.namespaces.add(argv[3])
        elif argv[:3] == ["ip", "netns", "delete"]:
            self.namespaces.discard(argv[3])
        elif argv[:3] == ["ip", "link", "add"]:
            self.link_set.add(argv[3])
        elif argv[:4] == ["ip", "link", "del", "dev"]:
            self.link_set.discard(argv[4])
        elif argv[:4] == ["ip", "-4", "rule", "add"]:
            self.rules.append({"priority": int(argv[5]), "iif": argv[7], "table": argv[9]})
        elif argv[:4] == ["ip", "-4", "rule", "del"]:
            self.rules = [r for r in self.rules if r["iif"] != argv[7]]
        return ""

    def netns_names(self) -> set[str]:
        return set(self.namespaces)

    def links(self) -> set[str]:
        return set(self.link_set)

    def read_sysctl(self, key: str) -> str | None:
        return self.sysctl.get(key)

    def write_sysctl(self, key: str, value: str) -> None:
        self.sysctl[key] = value
        self.log.append(f"sysctl {key}={value}")

    async def open_listeners(self, netns: Path, port: int) -> tuple[socket.socket, socket.socket]:
        self.listeners.append((netns, port))
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        udp.setblocking(False)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("127.0.0.1", 0))
        tcp.listen()
        tcp.setblocking(False)
        return udp, tcp


def manager(tmp_path: Path, system: FakeSystem) -> NetnsManager:
    return NetnsManager(system, netns_dir=NETNS_DIR, run_dir=tmp_path / "run")


def test_veth_names_map_to_policy_ids() -> None:
    assert veth_policy_id("pyvpn-h7") == 7
    assert veth_policy_id("pyvpn-h99") == 99
    for other in ("pyvpn-h0", "pyvpn-h100", "pyvpn-h07", "pyvpn-n7", "eth0", "pyvpn-h7x"):
        assert veth_policy_id(other) is None


async def test_prepare_creates_namespace_and_veth_cut_off(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    netns = manager(tmp_path, sys_)
    guard = await netns.prepare(RoutingPlan((plan(3),)))
    assert guard == ("tun0",)  # forwarding is off there, so pyvpn will own it
    assert sys_.log == [
        "ip netns add pyvpn-p3",
        "ip link add pyvpn-h3 type veth peer name pyvpn-n3 netns pyvpn-p3",
        "sysctl net/ipv4/conf/pyvpn-h3/forwarding=0",
        "sysctl net/ipv6/conf/pyvpn-h3/disable_ipv6=1",
        "ip addr replace 198.18.128.13/30 dev pyvpn-h3",
        "ip -n pyvpn-p3 link set lo up",
        "ip -n pyvpn-p3 addr replace 198.18.128.14/30 dev pyvpn-n3",
        "ip -n pyvpn-p3 link set pyvpn-n3 up",
        "ip -n pyvpn-p3 route replace default via 198.18.128.13 dev pyvpn-n3",
        "nsenter --net=/run/netns/pyvpn-p3 sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 "
        "net.ipv6.conf.default.disable_ipv6=1",
        "nsenter --net=/run/netns/pyvpn-p3 nft -f - <<nft",
    ]
    # Nothing is let out (host end up, forwarding on) before the commit.
    assert not any("pyvpn-h3 up" in line for line in sys_.log)
    assert netns.ready(3) is None
    sys_.log.clear()
    await netns.prepare(RoutingPlan((plan(3),)))
    assert sys_.log == []  # already configured: no subprocesses per apply


async def test_activate_lets_the_namespace_out_after_the_commit(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    netns = manager(tmp_path, sys_)
    p = RoutingPlan((plan(3, dns_stub_port=dns_stub_port(3)),))
    await netns.prepare(p)
    sys_.log.clear()
    await netns.activate(p)
    assert sys_.log == [
        "ip link set dev pyvpn-h3 up",
        "ip -n pyvpn-p3 neigh flush dev pyvpn-n3",
        "ip route replace 198.18.128.12/30 dev pyvpn-h3 table 1003",
        "ip -4 rule add pref 5203 iif pyvpn-h3 lookup 1003",
        "sysctl net/ipv4/conf/pyvpn-h3/forwarding=1",
        "sysctl net/ipv4/conf/tun0/forwarding=1",
    ]
    assert json.loads((tmp_path / "run" / "forwarding.json").read_text()) == ["tun0"]
    assert sys_.listeners == [(NETNS_DIR / "pyvpn-p3", 53)]
    assert netns.ready(3) == NETNS_DIR / "pyvpn-p3"
    await netns.close()


async def test_default_route_fallback_has_no_iif_rule(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    netns = manager(tmp_path, sys_)
    p = RoutingPlan((plan(2, route="main", interface=None),))
    # Replies come back on the host's default-route interface.
    assert await netns.prepare(p) == ("eth0",)
    await netns.activate(p)
    assert sys_.rules == []
    assert sys_.sysctl["net/ipv4/conf/tun0/forwarding"] == "0"
    assert sys_.sysctl["net/ipv4/conf/eth0/forwarding"] == "1"
    await netns.teardown()
    assert sys_.sysctl["net/ipv4/conf/eth0/forwarding"] == "0"


async def test_target_change_moves_forwarding_and_rule_stays(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    sys_.link_set.add("wg0")
    sys_.sysctl["net/ipv4/conf/wg0/forwarding"] = "0"
    netns = manager(tmp_path, sys_)
    first = RoutingPlan((plan(1),))
    await netns.prepare(first)
    await netns.activate(first)
    moved = RoutingPlan((plan(1, interface="wg0"),))
    # The ruleset committed in between still guards tun0 until it is reset.
    assert await netns.prepare(moved) == ("tun0", "wg0")
    await netns.activate(moved)
    assert sys_.sysctl["net/ipv4/conf/tun0/forwarding"] == "0"
    assert sys_.sysctl["net/ipv4/conf/wg0/forwarding"] == "1"
    assert json.loads((tmp_path / "run" / "forwarding.json").read_text()) == ["wg0"]
    assert len(sys_.rules) == 1


async def test_forwarding_someone_else_enabled_is_left_alone(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    sys_.sysctl["net/ipv4/conf/tun0/forwarding"] = "1"  # e.g. a router setup
    netns = manager(tmp_path, sys_)
    p = RoutingPlan((plan(1),))
    assert await netns.prepare(p) == ()
    await netns.activate(p)
    await netns.teardown()
    assert sys_.sysctl["net/ipv4/conf/tun0/forwarding"] == "1"


async def test_kill_switch_keeps_the_veth_and_the_iif_rule(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    netns = manager(tmp_path, sys_)
    p = RoutingPlan((plan(1, route="unreachable", interface=None),))
    await netns.prepare(p)
    await netns.activate(p)
    assert sys_.rules == [{"priority": 5201, "iif": "pyvpn-h1", "table": "1001"}]
    assert netns.ready(1) is not None


async def test_policy_losing_isolation_is_cut_off_before_the_commit(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    netns = manager(tmp_path, sys_)
    p = RoutingPlan((plan(1), plan(2)))
    await netns.prepare(p)
    await netns.activate(p)
    sys_.log.clear()
    only_two = RoutingPlan((plan(1, isolation="none"), plan(2)))
    await netns.prepare(only_two)
    assert sys_.log == [
        "sysctl net/ipv4/conf/pyvpn-h1/forwarding=0",
        "ip link set dev pyvpn-h1 down",
    ]
    assert netns.ready(1) is None
    sys_.log.clear()
    await netns.activate(only_two)
    assert "ip link del dev pyvpn-h1" in sys_.log
    assert "ip netns delete pyvpn-p1" in sys_.log
    assert "ip -4 rule del pref 5201 iif pyvpn-h1 lookup 1001" in sys_.log
    assert "pyvpn-p2" in sys_.namespaces and "pyvpn-h2" in sys_.link_set


async def test_teardown_deletes_veths_but_keeps_namespaces(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    netns = manager(tmp_path, sys_)
    p = RoutingPlan((plan(1, dns_stub_port=dns_stub_port(1)),))
    await netns.prepare(p)
    await netns.activate(p)
    await netns.teardown()
    assert "pyvpn-h1" not in sys_.link_set
    assert sys_.namespaces == {"pyvpn-p1"}  # apps inside keep running, cut off
    assert sys_.rules == []
    assert sys_.sysctl["net/ipv4/conf/tun0/forwarding"] == "0"
    assert netns.ready(1) is None
    # Re-enabling attaches a fresh veth to the same namespace.
    await netns.prepare(p)
    await netns.activate(p)
    assert "pyvpn-h1" in sys_.link_set
    assert sys_.log.count("ip netns add pyvpn-p1") == 1
    await netns.close()


async def test_a_fresh_manager_recovers_after_a_daemon_restart(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    first = manager(tmp_path, sys_)
    p = RoutingPlan((plan(4),))
    await first.prepare(p)
    await first.activate(p)
    sys_.log.clear()
    # A new daemon: the namespace and veth exist; it reconfigures in place
    # without recreating them (apps inside keep their namespace).
    second = manager(tmp_path, sys_)
    await second.prepare(p)
    assert not any(line.startswith(("ip netns add", "ip link add")) for line in sys_.log)
    await second.activate(p)
    assert second.ready(4) is not None
    assert len(sys_.rules) == 1  # not added twice
    # ...and can tear down what the previous daemon installed.
    third = manager(tmp_path, sys_)
    await third.teardown()
    assert sys_.rules == [] and "pyvpn-h4" not in sys_.link_set
    assert sys_.sysctl["net/ipv4/conf/tun0/forwarding"] == "0"
    # A later plan without the policy deletes the namespace left behind.
    await third.prepare(RoutingPlan())
    await third.activate(RoutingPlan())
    assert sys_.namespaces == set()


async def test_stale_veth_from_a_crash_is_cut_off_at_startup(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    sys_.link_set.add("pyvpn-h9")
    sys_.sysctl["net/ipv4/conf/pyvpn-h9/forwarding"] = "1"
    netns = manager(tmp_path, sys_)
    await netns.prepare(RoutingPlan())
    assert sys_.sysctl["net/ipv4/conf/pyvpn-h9/forwarding"] == "0"
    assert sys_.log[-1] == "ip link set dev pyvpn-h9 down"
    await netns.activate(RoutingPlan())
    assert "pyvpn-h9" not in sys_.link_set


async def test_unrelated_namespaces_are_never_deleted(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    sys_.namespaces |= {"pyvpn-tb-1234-host", "pyvpn-p", "pyvpn-p01", "other"}
    netns = manager(tmp_path, sys_)
    p = RoutingPlan((plan(1),))
    await netns.prepare(p)
    await netns.activate(p)
    await netns.activate(RoutingPlan())
    assert sys_.namespaces == {"pyvpn-tb-1234-host", "pyvpn-p", "pyvpn-p01", "other"}


async def test_without_isolation_nothing_runs(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    netns = manager(tmp_path, sys_)
    p = RoutingPlan((plan(1, isolation="none"),))
    assert await netns.prepare(p) == ()
    await netns.activate(p)
    await netns.teardown()
    assert sys_.log == []


async def test_failed_prepare_leaves_nothing_let_out(tmp_path: Path) -> None:
    sys_ = FakeSystem()
    sys_.fail = "nsenter"
    netns = manager(tmp_path, sys_)
    from pyvpn.platform.linux.netns import NetnsError

    with pytest.raises(NetnsError):
        await netns.prepare(RoutingPlan((plan(1),)))
    assert sys_.sysctl["net/ipv4/conf/pyvpn-h1/forwarding"] == "0"
    assert not any("up" in line and "pyvpn-h1" in line for line in sys_.log)
    sys_.fail = None
    sys_.log.clear()
    await netns.prepare(RoutingPlan((plan(1),)))
    assert any(line.startswith("nsenter") for line in sys_.log)  # configured again


def test_namespace_ruleset_redirects_all_dns_to_the_relay() -> None:
    script = render(build_netns_ruleset())
    assert "add chain inet pyvpn_ns dns { type nat hook output priority -100;" in script
    assert "meta l4proto { tcp, udp } th dport 53 redirect to :53" in script


# --- DNS relay -------------------------------------------------------------------


class _Stub(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        assert self.transport is not None
        self.transport.sendto(b"answer:" + data, addr)


async def test_relay_forwards_udp_and_tcp_to_the_stub(tmp_path: Path) -> None:
    loop = asyncio.get_running_loop()
    stub_transport, _ = await loop.create_datagram_endpoint(_Stub, local_addr=("127.0.0.1", 0))
    port = stub_transport.get_extra_info("sockname")[1]

    async def tcp_stub(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(100)
        writer.write(b"tcp:" + data)
        await writer.drain()
        writer.close()

    tcp_server = await asyncio.start_server(tcp_stub, "127.0.0.1", port)
    sys_ = FakeSystem()
    udp, tcp = await sys_.open_listeners(Path("/x"), 53)
    relay = DnsRelay(udp, tcp, ("127.0.0.1", port), timeout=2)
    await relay.start()
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setblocking(False)
        client.connect(udp.getsockname())
        await loop.sock_sendall(client, b"q1")
        assert await asyncio.wait_for(loop.sock_recv(client, 100), 2) == b"answer:q1"
        client.close()

        reader, writer = await asyncio.open_connection(*tcp.getsockname())
        writer.write(b"q2")
        await writer.drain()
        assert await asyncio.wait_for(reader.read(100), 2) == b"tcp:q2"
        writer.close()
    finally:
        await relay.close()
        stub_transport.close()
        tcp_server.close()


async def test_relay_drops_queries_when_the_stub_is_silent() -> None:
    loop = asyncio.get_running_loop()
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    sys_ = FakeSystem()
    udp, tcp = await sys_.open_listeners(Path("/x"), 53)
    relay = DnsRelay(udp, tcp, silent.getsockname(), timeout=0.2)
    await relay.start()
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setblocking(False)
        client.connect(udp.getsockname())
        await loop.sock_sendall(client, b"q")
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(loop.sock_recv(client, 100), 0.5)
        client.close()
    finally:
        await relay.close()
        silent.close()


# --- isolated launch -------------------------------------------------------------

_FAKE_HELPER = """
import json, os, sys
fd = int(sys.argv[1])
data = b""
while chunk := os.read(fd, 65536):
    data += chunk
if not data:
    sys.exit(125)
spec = json.loads(data)
print(json.dumps(spec))
"""


def command(**kw: Any) -> IsolatedCommand:
    base: dict[str, Any] = {
        "policy_id": 2,
        "argv": ("app", "--flag"),
        "env": {"HOME": "/home/u"},
        "cwd": "/home/u",
        "umask": 0o022,
        "uid": 1000,
        "gid": 1000,
        "client_pid": 4242,
        "client_pidfd": None,
    }
    base.update(kw)
    return IsolatedCommand(**base)


def fake_proc(tmp_path: Path, out: Path) -> Path:
    proc = tmp_path / "proc"
    (proc / "4242" / "fd").mkdir(parents=True)
    (proc / "4242" / "status").write_text("Name:\tpyvpn\nGroups:\t27 1000 \nUid:\t1000\n")
    (proc / "4242" / "fd" / "0").write_text("")
    for n in (1, 2):
        os.symlink(out, proc / "4242" / "fd" / str(n))
    return proc


async def test_spawn_places_the_helper_before_sending_the_spec(tmp_path: Path) -> None:
    out = tmp_path / "out.txt"
    out.write_text("")
    proc = fake_proc(tmp_path, out)
    netns = tmp_path / "ns"
    netns.write_text("")
    order: list[str] = []

    async def place(pid: int) -> None:
        order.append(f"place {pid}")

    child = await spawn_isolated(
        command(),
        netns=netns,
        place=place,
        verify_peer=lambda: order.append("verify"),
        helper=[sys.executable, "-c", _FAKE_HELPER],
        proc=proc,
    )
    assert await child.wait() == 0
    assert order == ["verify", f"place {child.pid}", "verify"]
    spec = json.loads(out.read_text())
    st = os.stat(netns)
    assert spec == {
        "netns": str(netns),
        "netns_id": [st.st_dev, st.st_ino],
        "uid": 1000,
        "gid": 1000,
        "groups": [27, 1000],
        "argv": ["app", "--flag"],
        "env": {"HOME": "/home/u"},
        "cwd": "/home/u",
        "umask": 0o022,
    }


async def test_failed_placement_never_sends_the_spec(tmp_path: Path) -> None:
    out = tmp_path / "out.txt"
    out.write_text("")
    netns = tmp_path / "ns"
    netns.write_text("")
    started: list[int] = []

    async def place(pid: int) -> None:
        started.append(pid)
        raise RuntimeError("cgroup is stale")

    with pytest.raises(RuntimeError, match="stale"):
        await spawn_isolated(
            command(),
            netns=netns,
            place=place,
            verify_peer=lambda: None,
            helper=[sys.executable, "-c", _FAKE_HELPER],
            proc=fake_proc(tmp_path, out),
        )
    assert started and out.read_text() == ""  # helper got EOF, ran nothing


async def test_spawn_refuses_a_caller_that_exited(tmp_path: Path) -> None:
    netns = tmp_path / "ns"
    netns.write_text("")
    placed: list[int] = []

    async def place(pid: int) -> None:
        placed.append(pid)

    def gone() -> None:
        raise PermissionError("caller exited")

    with pytest.raises(PermissionError):
        await spawn_isolated(
            command(),
            netns=netns,
            place=place,
            verify_peer=gone,
            helper=[sys.executable, "-c", _FAKE_HELPER],
            proc=fake_proc(tmp_path, tmp_path / "o"),
        )
    assert placed == []


def test_client_fd_falls_back_to_dev_null(tmp_path: Path) -> None:
    fd = client_fd(999999, None, 1, proc=tmp_path)
    try:
        assert os.path.samefile(f"/dev/fd/{fd}", os.devnull) or os.fstat(fd).st_rdev
    finally:
        os.close(fd)


def test_supplementary_groups_are_read_from_proc(tmp_path: Path) -> None:
    proc = fake_proc(tmp_path, tmp_path / "o")
    assert supplementary_groups(4242, proc=proc) == (27, 1000)


# --- LinuxBackend ordering -------------------------------------------------------


class _LoggingSystem(FakeSystem):
    def __init__(self, shared: list[str]) -> None:
        super().__init__()
        self.shared = shared

    async def run(self, argv: Sequence[str], *, input: str | None = None) -> str:
        out = await super().run(argv, input=input)
        if argv[:3] != ["ip", "-j", "-4"]:
            self.shared.append(" ".join(argv))
        return out

    def write_sysctl(self, key: str, value: str) -> None:
        super().write_sysctl(key, value)
        self.shared.append(f"sysctl {key}={value}")


def _backend(tmp_path: Path) -> tuple[Any, list[str], Any]:
    from pyvpn.platform.linux.backend import LinuxBackend
    from tests.platform.test_linux_backend import FakeNft, proc_sys
    from tests.routing._fakes import FakeNetlink

    for pid in (1, 2):
        (tmp_path / policy_cgroup(pid)).mkdir(parents=True)
    log: list[str] = []
    nft = FakeNft(log)
    netns = NetnsManager(_LoggingSystem(log), netns_dir=NETNS_DIR, run_dir=tmp_path / "run")
    backend = LinuxBackend(
        nft=nft,
        netlink=FakeNetlink(log),
        cgroup_root=tmp_path,
        proc_sys=proc_sys(tmp_path),
        netns=netns,
    )
    return backend, log, nft


async def test_backend_lets_namespaces_out_only_after_the_commit(tmp_path: Path) -> None:
    backend, log, nft = _backend(tmp_path)
    await backend.apply(RoutingPlan((plan(1),)))
    created = log.index("ip link add pyvpn-h1 type veth peer name pyvpn-n1 netns pyvpn-p1")
    guard, commit = log.index("nft guard"), log.index("nft commit")
    up = log.index("ip link set dev pyvpn-h1 up")
    forwarding = log.index("sysctl net/ipv4/conf/pyvpn-h1/forwarding=1")
    assert created < guard < commit < up < forwarding
    assert "add chain inet pyvpn_guard forward" in nft.scripts[0]
    assert 'meta iifname "pyvpn-h1" jump n1' in nft.scripts[-1]
    assert 'meta iifname "tun0" drop' in nft.scripts[-1]  # forwarding pyvpn enabled
    await backend.close()


async def test_backend_teardown_cuts_namespaces_off_before_the_table(tmp_path: Path) -> None:
    backend, log, _ = _backend(tmp_path)
    await backend.apply(RoutingPlan((plan(1),)))
    log.clear()
    await backend.teardown()
    assert log.index("ip link del dev pyvpn-h1") < log.index("nft guard") < log.index("nft commit")


async def test_backend_spawn_requires_an_installed_namespace(tmp_path: Path) -> None:
    from pyvpn.apps.cgroups import CgroupError, CgroupManager

    backend, _, _ = _backend(tmp_path)
    cgroups = CgroupManager(tmp_path)
    with pytest.raises(CgroupError, match="not installed"):
        await backend.spawn_isolated(cgroups, command(policy_id=1), lambda: None)
    await backend.apply(RoutingPlan((plan(1, isolation="none"),)))
    with pytest.raises(CgroupError, match="not installed"):
        await backend.spawn_isolated(cgroups, command(policy_id=1), lambda: None)
    await backend.close()


async def test_backend_failed_namespace_setup_changes_no_rules(tmp_path: Path) -> None:
    backend, _, nft = _backend(tmp_path)
    backend._netns._sys.fail = "ip link add"
    from pyvpn.platform.linux.netns import NetnsError

    with pytest.raises(NetnsError):
        await backend.apply(RoutingPlan((plan(1),)))
    assert nft.scripts == []
