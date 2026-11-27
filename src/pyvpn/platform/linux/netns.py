"""Per-policy network namespaces for ``isolation: netns`` (PLAN.md §3.6).

Each policy plan with ``isolation="netns"`` gets a named namespace
(``/run/netns/pyvpn-p<id>``) joined to the host by a veth pair::

    namespace                         host
    pyvpn-n<id> 198.18.128.<4id+2> ── pyvpn-h<id> 198.18.128.<4id+1>
    default via the host end          forwarded only as the policy allows

The namespace has no IPv6 and no other interface, and it is owned by root:
an unprivileged app inside cannot change it. Its only way out is the veth,
and the host forwards that veth like the policy's apps (``netfilter.ruleset``
chains ``forward`` and ``n<id>``, plus an ``iif`` routing rule into the
policy table). Port 53 inside the namespace is redirected to a relay the
daemon runs there, which forwards queries to the policy's DNS stub on the
host loopback.

Ordering keeps the namespace fail-closed:

* ``prepare`` (before the nft commit) cuts off veths of policies that lost
  isolation and creates new veths with forwarding off and the host end down;
* the backend's route guard drops everything forwarded from the namespace
  range while routes and rules change;
* ``activate`` (after the commit) brings the host end up and turns
  forwarding on, only once the forward rules for it are installed;
* ``teardown`` deletes the veths before the nft table goes away.

Namespaces survive a daemon restart and ``disable`` (apps inside keep running,
cut off until a veth is attached again). A namespace whose policy no longer
asks for isolation is deleted on the next apply.

IPv4 forwarding is a per-interface setting on Linux, checked on the
interface a packet arrives on. Replies come back on the target interface, so
``activate`` turns forwarding on for each active target that had it off,
records that in ``forwarding.json`` under the runtime directory, and turns it
off again once no namespace uses the target. The ruleset drops new forwarded
connections arriving on those interfaces.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import errno
import json
import logging
import os
import re
import socket
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from pyvpn.constants import (
    NETNS_PREFIX,
    RULE_PREF_BASE,
    netns_host_address,
    netns_host_veth,
    netns_peer_address,
    netns_peer_veth,
    netns_subnet,
    policy_netns,
    policy_rule_pref,
    policy_table,
)
from pyvpn.netfilter.render import render
from pyvpn.netfilter.ruleset import build_netns_ruleset
from pyvpn.routing.apply import PROC_SYS
from pyvpn.state import PolicyPlan, RoutingPlan

log = logging.getLogger(__name__)

NETNS_DIR = Path("/run/netns")
RUN_DIR = Path("/run/pyvpn")
CLONE_NEWNET = 0x40000000
_VETH = re.compile(r"pyvpn-h([1-9][0-9]?)")
_COMMAND_TIMEOUT = 10.0
DNS_PORT = 53


class NetnsError(RuntimeError):
    """A namespace operation failed."""


def setns(fd: int, nstype: int = CLONE_NEWNET) -> None:
    """Move the calling thread into the namespace ``fd`` refers to."""
    native = getattr(os, "setns", None)
    if native is not None:  # Python 3.12+
        native(fd, nstype)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(fd, nstype) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


class NetnsSystem(Protocol):
    """The host operations the manager needs (a fake in unit tests)."""

    async def run(self, argv: Sequence[str], *, input: str | None = None) -> str:
        """Run a command; raise ``NetnsError`` when it fails."""

    def netns_names(self) -> set[str]:
        """Names registered in ``/run/netns``."""

    def links(self) -> set[str]:
        """Interface names in the daemon's network namespace."""

    def stat(self, path: Path) -> tuple[int, int] | None:
        """``(st_dev, st_ino)`` of a namespace handle, or None when it is gone."""

    def ifindex(self, name: str) -> int | None:
        """The index of an interface, or None when it does not exist."""

    def read_sysctl(self, key: str) -> str | None:
        """A ``/proc/sys`` value (``net/ipv4/...``), or None when it does not exist."""

    def write_sysctl(self, key: str, value: str) -> None: ...

    async def open_listeners(self, netns: Path, port: int) -> tuple[socket.socket, socket.socket]:
        """UDP and listening TCP sockets bound to ``0.0.0.0:port`` inside ``netns``."""


class HostSystem:
    """``NetnsSystem`` on the real host: ``ip``, ``nsenter`` and ``/proc/sys``."""

    def __init__(self, *, proc_sys: Path = PROC_SYS, netns_dir: Path = NETNS_DIR) -> None:
        self.proc_sys = proc_sys
        self.netns_dir = netns_dir

    async def run(self, argv: Sequence[str], *, input: str | None = None) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise NetnsError(f"cannot run {argv[0]}: {exc}") from exc
        try:
            async with asyncio.timeout(_COMMAND_TIMEOUT):
                out, err = await proc.communicate(input.encode() if input is not None else None)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()
            raise NetnsError(f"{' '.join(argv)}: timed out") from None
        if proc.returncode:
            detail = err.decode(errors="replace").strip()
            raise NetnsError(f"{' '.join(argv)} failed ({proc.returncode}): {detail}")
        return out.decode(errors="replace")

    def netns_names(self) -> set[str]:
        try:
            return {entry.name for entry in os.scandir(self.netns_dir)}
        except OSError:
            return set()

    def links(self) -> set[str]:
        return {name for _, name in socket.if_nameindex()}

    def stat(self, path: Path) -> tuple[int, int] | None:
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (st.st_dev, st.st_ino)

    def ifindex(self, name: str) -> int | None:
        try:
            return socket.if_nametoindex(name)
        except OSError:
            return None

    def read_sysctl(self, key: str) -> str | None:
        try:
            return (self.proc_sys / key).read_text().strip()
        except OSError:
            return None

    def write_sysctl(self, key: str, value: str) -> None:
        (self.proc_sys / key).write_text(f"{value}\n")

    async def open_listeners(self, netns: Path, port: int) -> tuple[socket.socket, socket.socket]:
        pair: tuple[socket.socket, socket.socket] = await _in_netns(netns, lambda: _bind_pair(port))
        return pair


def _bind_pair(port: int) -> tuple[socket.socket, socket.socket]:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        udp.bind(("0.0.0.0", port))
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("0.0.0.0", port))
        tcp.listen(64)
        udp.setblocking(False)
        tcp.setblocking(False)
    except BaseException:
        udp.close()
        tcp.close()
        raise
    return udp, tcp


async def _in_netns(netns: Path, create: Any) -> Any:
    """Run ``create`` on a throwaway thread inside ``netns``.

    A dedicated thread, never the executor pool: a pool thread left in the
    wrong namespace would make later work (route sync) act on the namespace.
    Sockets keep the namespace they were created in.
    """
    loop = asyncio.get_running_loop()
    done: asyncio.Future[Any] = loop.create_future()

    def work() -> None:
        try:
            fd = os.open(netns, os.O_RDONLY | os.O_CLOEXEC)
            try:
                setns(fd)
            finally:
                os.close(fd)
            result = create()
        except BaseException as exc:
            loop.call_soon_threadsafe(_settle, done, None, exc)
        else:
            loop.call_soon_threadsafe(_settle, done, result, None)
        # The thread ends here, still inside the namespace; nothing reuses it.

    threading.Thread(target=work, name="pyvpn-netns", daemon=True).start()
    return await done


def _settle(fut: asyncio.Future[Any], result: Any, exc: BaseException | None) -> None:
    if fut.cancelled():
        if result is not None:
            for sock in result:
                sock.close()
        return
    if exc is not None:
        fut.set_exception(exc)
    else:
        fut.set_result(result)


# --- DNS relay -------------------------------------------------------------------


class DnsRelay:
    """Forward DNS from a namespace's port 53 to the policy's stub.

    The listeners live inside the namespace; the upstream sockets are opened
    by the daemon in its own namespace, to ``127.0.0.1:<stub port>``. The
    relay only shuttles bytes: the stub applies the policy (target-bound
    upstream, SERVFAIL while the target is down).
    """

    MAX_UDP_INFLIGHT = 256
    MAX_TCP_CLIENTS = 64

    def __init__(
        self,
        udp: socket.socket,
        tcp: socket.socket,
        upstream: tuple[str, int],
        *,
        timeout: float = 5.0,
    ) -> None:
        self._udp_sock = udp
        self._tcp_sock = tcp
        self.upstream = upstream
        self._timeout = timeout
        self._udp: asyncio.DatagramTransport | None = None
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        relay = self

        class _Udp(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                relay._on_udp(data, addr)

        transport, _ = await loop.create_datagram_endpoint(_Udp, sock=self._udp_sock)
        self._udp = transport
        self._server = await asyncio.start_server(self._on_tcp, sock=self._tcp_sock)

    def _spawn(self, coro: Any) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _on_udp(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(self._tasks) >= self.MAX_UDP_INFLIGHT:
            return  # the client retries; never queue without bound
        self._spawn(self._relay_udp(data, addr))

    async def _relay_udp(self, data: bytes, addr: tuple[str, int]) -> None:
        loop = asyncio.get_running_loop()
        reply: asyncio.Future[bytes] = loop.create_future()

        class _Upstream(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, _: tuple[str, int]) -> None:
                if not reply.done():
                    reply.set_result(data)

            def error_received(self, exc: Exception) -> None:
                if not reply.done():
                    reply.set_exception(exc)

        try:
            transport, _ = await loop.create_datagram_endpoint(_Upstream, remote_addr=self.upstream)
        except OSError:
            return
        try:
            transport.sendto(data)
            answer = await asyncio.wait_for(reply, self._timeout)
        except (OSError, TimeoutError):
            return
        finally:
            transport.close()
        if self._udp is not None and not self._udp.is_closing():
            self._udp.sendto(answer, addr)

    async def _on_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self._tasks) >= self.MAX_TCP_CLIENTS + self.MAX_UDP_INFLIGHT:
            writer.close()
            return
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(*self.upstream), self._timeout
            )
        except (OSError, TimeoutError):
            writer.close()
            return
        try:
            await asyncio.gather(self._pipe(reader, up_writer), self._pipe(up_reader, writer))
        finally:
            for w in (writer, up_writer):
                w.close()

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), self._timeout * 6)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        except (OSError, TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            with contextlib.suppress(OSError, RuntimeError):
                if writer.can_write_eof():
                    writer.write_eof()

    async def close(self) -> None:
        if self._udp is not None:
            self._udp.close()
        else:
            self._udp_sock.close()
        if self._server is not None:
            self._server.close()
        else:
            self._tcp_sock.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self._server is not None:
            with contextlib.suppress(Exception):
                await self._server.wait_closed()


# --- manager ---------------------------------------------------------------------


@dataclass(frozen=True)
class _IifRule:
    priority: int
    iif: str
    table: int


@dataclass(frozen=True)
class _Namespace:
    """What pyvpn recorded when it created a namespace (ownership marker).

    ``inode`` identifies the namespace handle; a re-created namespace has a
    different inode, so the marker also tells a surviving pair that its
    namespace is gone. ``ifindex`` identifies the host end of the veth.
    """

    inode: tuple[int, int]
    veth: str
    ifindex: int


def veth_policy_id(name: str) -> int | None:
    """The policy id of a host-side veth name (``pyvpn-h<id>``), else None."""
    m = _VETH.fullmatch(name)
    return int(m.group(1)) if m else None


class NetnsManager:
    def __init__(
        self,
        system: NetnsSystem | None = None,
        *,
        proc_sys: Path = PROC_SYS,
        netns_dir: Path = NETNS_DIR,
        run_dir: Path = RUN_DIR,
        prefix: str = NETNS_PREFIX,
    ) -> None:
        self._sys: NetnsSystem = system or HostSystem(proc_sys=proc_sys, netns_dir=netns_dir)
        self._netns_dir = netns_dir
        self._record = run_dir / "forwarding.json"
        self._markers_path = run_dir / "netns.json"
        self._prefix = prefix
        self._ns_name = re.compile(re.escape(prefix) + r"([1-9][0-9]?)")
        self._configured: set[int] = set()
        self._ready: dict[int, Path] = {}
        self._relays: dict[int, DnsRelay] = {}

    # --- queries --------------------------------------------------------------

    def path(self, policy_id: int) -> Path:
        return self._netns_dir / policy_netns(policy_id, self._prefix)

    def ready(self, policy_id: int) -> Path | None:
        """The namespace path once ``activate`` finished for the policy."""
        return self._ready.get(policy_id)

    @staticmethod
    def _wanted(plan: RoutingPlan) -> dict[int, PolicyPlan]:
        return {p.policy_id: p for p in plan.policies if p.isolation == "netns"}

    def _ipv6(self) -> bool:
        return self._sys.read_sysctl("net/ipv6/conf/all/disable_ipv6") is not None

    def _recorded(self) -> set[str]:
        try:
            names = json.loads(self._record.read_text())
        except FileNotFoundError:
            return set()
        except (OSError, ValueError) as exc:
            log.warning("ignoring unreadable %s: %s", self._record, exc)
            return set()
        return {n for n in names if isinstance(n, str)} if isinstance(names, list) else set()

    def _save_record(self, names: set[str]) -> None:
        self._record.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._record.with_name(self._record.name + ".tmp")
        tmp.write_text(json.dumps(sorted(names)) + "\n")
        os.replace(tmp, self._record)

    def _markers(self) -> dict[int, _Namespace]:
        """The ownership markers written when pyvpn created a namespace."""
        try:
            doc = json.loads(self._markers_path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log.warning("ignoring unreadable %s: %s", self._markers_path, exc)
            return {}
        entries = doc.get("namespaces") if isinstance(doc, dict) else None
        if not isinstance(entries, dict):
            return {}
        out: dict[int, _Namespace] = {}
        for key, value in entries.items():
            try:
                pid = int(key)
                inode = (int(value["inode"][0]), int(value["inode"][1]))
                veth = str(value["veth"])
                ifindex = int(value["ifindex"])
            except (KeyError, TypeError, ValueError, IndexError):
                continue
            out[pid] = _Namespace(inode, veth, ifindex)
        return out

    def _save_markers(self, markers: dict[int, _Namespace]) -> None:
        self._markers_path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "version": 1,
            "namespaces": {
                str(pid): {"inode": list(m.inode), "veth": m.veth, "ifindex": m.ifindex}
                for pid, m in sorted(markers.items())
            },
        }
        tmp = self._markers_path.with_name(self._markers_path.name + ".tmp")
        tmp.write_text(json.dumps(doc, sort_keys=True) + "\n")
        os.replace(tmp, self._markers_path)

    def _mark(self, pid: int) -> None:
        """Record that the namespace and veth for ``pid`` are pyvpn's."""
        inode = self._sys.stat(self.path(pid))
        ifindex = self._sys.ifindex(netns_host_veth(pid))
        if inode is None or ifindex is None:
            raise NetnsError(f"cannot record ownership of {self.path(pid)}")
        markers = self._markers()
        markers[pid] = _Namespace(inode, netns_host_veth(pid), ifindex)
        self._save_markers(markers)

    def _unmark(self, pid: int) -> None:
        markers = self._markers()
        if markers.pop(pid, None) is not None:
            self._save_markers(markers)

    async def _peer_inside(self, ns: str, peer: str) -> bool:
        """Whether the veth peer link is actually in the namespace ``ns``."""
        try:
            await self._sys.run(["ip", "-n", ns, "link", "show", peer])
        except NetnsError:
            return False
        return True

    async def _owned(self, pid: int, ns: str, marker: _Namespace | None) -> bool:
        """Whether an existing namespace/veth is pyvpn's, not a foreign one.

        The marker is authoritative when its inode still matches. Without a
        marker (an upgrade from a version that did not write one, or a crash
        between create and mark) the strict signature is the veth peer sitting
        inside the namespace named ``pyvpn-p<id>``.
        """
        inode = self._sys.stat(self.path(pid))
        if marker is not None and inode is not None and marker.inode == inode:
            return True
        return await self._peer_inside(ns, netns_peer_veth(pid))

    async def _targets(self, wanted: dict[int, PolicyPlan]) -> set[str]:
        """Interfaces replies to the namespaces arrive on (forwarding must be on).

        For the default-route fallback (route ``main``) these are the devices
        of the main table's IPv4 default routes at the time of the apply.
        """
        out = {p.interface for p in wanted.values() if p.route == "dev" and p.interface}
        if any(p.route == "main" for p in wanted.values()):
            listing = await self._sys.run(["ip", "-j", "-4", "route", "show", "default"])
            for entry in json.loads(listing or "[]"):
                dev = entry.get("dev")
                if isinstance(dev, str) and veth_policy_id(dev) is None:
                    out.add(dev)
        return out

    def _forwarding(self, iface: str) -> str | None:
        return self._sys.read_sysctl(f"net/ipv4/conf/{iface}/forwarding")

    # --- apply ----------------------------------------------------------------

    async def prepare(self, plan: RoutingPlan) -> tuple[str, ...]:
        """Before the nft commit: cut off stale veths, create missing ones.

        Returns the target interfaces whose forwarding pyvpn controls once
        this plan is active (``build_ruleset(forwarding_guard=...)``).
        """
        wanted = self._wanted(plan)
        links = self._sys.links()
        for name in sorted(links):
            pid = veth_policy_id(name)
            if pid is not None and pid not in wanted and await self._owns_policy(pid):
                await self._cut_off(name)
                self._ready.pop(pid, None)
                self._configured.discard(pid)
        if wanted:
            names = self._sys.netns_names()
            for pid in sorted(wanted):
                await self._ensure(pid, names, links)
        guard = self._recorded()
        for iface in await self._targets(wanted):
            if iface in guard or self._forwarding(iface) == "0":
                guard.add(iface)
        return tuple(sorted(guard))

    async def _cut_off(self, veth: str) -> None:
        with contextlib.suppress(OSError):
            self._sys.write_sysctl(f"net/ipv4/conf/{veth}/forwarding", "0")
        await self._sys.run(["ip", "link", "set", "dev", veth, "down"])

    async def _ensure(self, pid: int, names: set[str], links: set[str]) -> None:
        ns = policy_netns(pid, self._prefix)
        host, peer = netns_host_veth(pid), netns_peer_veth(pid)
        marker = self._markers().get(pid)
        created = False
        if ns not in names:
            self._configured.discard(pid)
            await self._sys.run(["ip", "netns", "add", ns])
            created = True
        if host not in links:
            self._configured.discard(pid)
            self._ready.pop(pid, None)
            if not created and not await self._owned(pid, ns, marker):
                # A namespace without its veth: adopt it only when it is pyvpn's.
                raise NetnsError(
                    f"{ns} exists without a pyvpn veth and is not marked as pyvpn's; "
                    "refusing to adopt it"
                )
            await self._sys.run(
                ["ip", "link", "add", host, "type", "veth", "peer", "name", peer, "netns", ns]
            )
            # A new interface copies conf/default/forwarding; keep it off
            # until the forward rules for it are committed.
            self._sys.write_sysctl(f"net/ipv4/conf/{host}/forwarding", "0")
        if pid in self._configured:
            return
        run = self._sys.run
        if self._ipv6():
            self._sys.write_sysctl(f"net/ipv6/conf/{host}/disable_ipv6", "1")
        await run(["ip", "addr", "replace", f"{netns_host_address(pid)}/30", "dev", host])
        await run(["ip", "-n", ns, "link", "set", "lo", "up"])
        await run(["ip", "-n", ns, "addr", "replace", f"{netns_peer_address(pid)}/30", "dev", peer])
        await run(["ip", "-n", ns, "link", "set", peer, "up"])
        await run(
            [
                "ip",
                "-n",
                ns,
                "route",
                "replace",
                "default",
                "via",
                str(netns_host_address(pid)),
                "dev",
                peer,
            ]
        )
        enter = ["nsenter", f"--net={self.path(pid)}"]
        if self._ipv6():
            await run(
                [
                    *enter,
                    "sysctl",
                    "-q",
                    "-w",
                    "net.ipv6.conf.all.disable_ipv6=1",
                    "net.ipv6.conf.default.disable_ipv6=1",
                ]
            )
        await run([*enter, "nft", "-f", "-"], input=render(build_netns_ruleset()))
        self._configured.add(pid)
        self._mark(pid)

    async def _owns_policy(self, pid: int) -> bool:
        """Whether the namespace/veth for ``pid`` may be deleted as pyvpn's.

        A matching marker or a peer inside the namespace is proof. A veth
        whose namespace is already gone is a leftover of ours; a namespace
        that is not ours is left alone.
        """
        ns = policy_netns(pid, self._prefix)
        if ns not in self._sys.netns_names():
            return True
        return await self._owned(pid, ns, self._markers().get(pid))

    async def activate(self, plan: RoutingPlan) -> None:
        """After the nft commit: let each namespace out through its rules."""
        wanted = self._wanted(plan)
        run = self._sys.run
        links = self._sys.links()
        stale_ns = sorted(
            name
            for name in self._sys.netns_names()
            if (m := self._ns_name.fullmatch(name)) and int(m.group(1)) not in wanted
        )
        if not wanted and not stale_ns and not any(veth_policy_id(n) is not None for n in links):
            # Nothing isolated now or before: skip the subprocesses (rules
            # naming a veth that does not exist match no packet).
            await self._sync_forwarding(set())
            await self._close_relays(set())
            self._ready.clear()
            return
        for pid in sorted(wanted):
            host = netns_host_veth(pid)
            await run(["ip", "link", "set", "dev", host, "up"])
            if pid not in self._ready:
                # Lookups of the gateway made while the namespace was cut off
                # failed; forget them so the first connection need not wait.
                ns = policy_netns(pid, self._prefix)
                await run(["ip", "-n", ns, "neigh", "flush", "dev", netns_peer_veth(pid)])
            await run(
                [
                    "ip",
                    "route",
                    "replace",
                    str(netns_subnet(pid)),
                    "dev",
                    host,
                    "table",
                    str(policy_table(pid)),
                ]
            )
        await self._sync_rules(
            {
                _IifRule(policy_rule_pref(pid), netns_host_veth(pid), policy_table(pid))
                for pid, p in wanted.items()
                if p.route != "main"
            }
        )
        for pid in sorted(wanted):
            self._sys.write_sysctl(f"net/ipv4/conf/{netns_host_veth(pid)}/forwarding", "1")
        await self._sync_forwarding(await self._targets(wanted))
        for pid, p in sorted(wanted.items()):
            await self._sync_relay(pid, p.dns_stub_port)
            self._ready[pid] = self.path(pid)

        for name in sorted(links):
            vid = veth_policy_id(name)
            if vid is not None and vid not in wanted and await self._owns_policy(vid):
                await run(["ip", "link", "del", "dev", name])
        for name in stale_ns:
            pid = int(self._ns_name.fullmatch(name).group(1))  # type: ignore[union-attr]
            if await self._owns_policy(pid):
                await run(["ip", "netns", "delete", name])
                self._unmark(pid)
            else:
                log.warning("leaving %s: it is not marked as pyvpn's", name)
        await self._close_relays(set(wanted))
        for pid in sorted(set(self._ready) - set(wanted)):
            del self._ready[pid]

    async def teardown(self) -> None:
        """Delete every pyvpn veth (namespaces stay, cut off), rules and relays."""
        self._ready.clear()
        veths = []
        for name in sorted(self._sys.links()):
            pid = veth_policy_id(name)
            if pid is not None and await self._owns_policy(pid):
                veths.append(name)
        for name in veths:
            with contextlib.suppress(OSError):
                self._sys.write_sysctl(f"net/ipv4/conf/{name}/forwarding", "0")
            await self._sys.run(["ip", "link", "del", "dev", name])
        self._configured.clear()
        if veths:
            await self._sync_rules(set())
        await self._sync_forwarding(set())
        await self._close_relays(set())

    async def close(self) -> None:
        """Stop the relays (daemon shutdown); namespaces and veths stay."""
        await self._close_relays(set())

    async def _close_relays(self, keep: set[int]) -> None:
        for pid in sorted(set(self._relays) - keep):
            await self._relays.pop(pid).close()

    async def _sync_rules(self, wanted: set[_IifRule]) -> None:
        current: set[_IifRule] = set()
        for entry in json.loads(await self._sys.run(["ip", "-j", "-4", "rule", "list"]) or "[]"):
            iif, prio, table = entry.get("iif"), entry.get("priority"), entry.get("table")
            if not isinstance(iif, str) or veth_policy_id(iif) is None:
                continue
            if not isinstance(prio, int) or not RULE_PREF_BASE < prio <= RULE_PREF_BASE + 99:
                continue
            with contextlib.suppress(TypeError, ValueError):
                current.add(_IifRule(prio, iif, int(table)))
        for rule in sorted(wanted - current, key=lambda r: r.priority):
            await self._sys.run(
                [
                    "ip",
                    "-4",
                    "rule",
                    "add",
                    "pref",
                    str(rule.priority),
                    "iif",
                    rule.iif,
                    "lookup",
                    str(rule.table),
                ]
            )
        for rule in sorted(current - wanted, key=lambda r: r.priority):
            await self._sys.run(
                [
                    "ip",
                    "-4",
                    "rule",
                    "del",
                    "pref",
                    str(rule.priority),
                    "iif",
                    rule.iif,
                    "lookup",
                    str(rule.table),
                ]
            )

    async def _sync_forwarding(self, targets: set[str]) -> None:
        record = self._recorded()
        links = self._sys.links()
        flip = {t for t in targets if t not in record and self._forwarding(t) == "0"}
        if flip:
            # Record first: a crash after the write still lets a later run undo it.
            record |= flip
            self._save_record(record)
            for iface in sorted(flip):
                self._sys.write_sysctl(f"net/ipv4/conf/{iface}/forwarding", "1")
                log.info("enabled IPv4 forwarding on %s for namespace replies", iface)
        for iface in sorted(record & targets):
            # A target that was re-created starts with forwarding off again.
            if iface in links and self._forwarding(iface) == "0":
                self._sys.write_sysctl(f"net/ipv4/conf/{iface}/forwarding", "1")
        stale = record - targets
        if stale:
            for iface in sorted(stale):
                if iface in links:
                    with contextlib.suppress(OSError):
                        self._sys.write_sysctl(f"net/ipv4/conf/{iface}/forwarding", "0")
            self._save_record(record - stale)

    async def _sync_relay(self, pid: int, stub_port: int | None) -> None:
        relay = self._relays.get(pid)
        if relay is not None and stub_port is not None and relay.upstream[1] == stub_port:
            return
        if relay is not None:
            await self._relays.pop(pid).close()
        if stub_port is None:
            return
        try:
            udp, tcp = await self._sys.open_listeners(self.path(pid), DNS_PORT)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                raise NetnsError(f"port 53 is already in use inside {self.path(pid)}") from exc
            raise
        relay = DnsRelay(udp, tcp, ("127.0.0.1", stub_port))
        await relay.start()
        self._relays[pid] = relay
