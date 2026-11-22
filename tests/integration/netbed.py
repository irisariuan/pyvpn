"""The network-namespace test bed from PLAN.md §8 (stream I)."""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

PREFIX = "pyvpn-tb-"
WAN_NETWORK = "192.0.2"  # RFC 5737 TEST-NET-1: host .2, internet .1
VPN_NETWORK = "198.51.100"  # RFC 5737 TEST-NET-2: host .2, internet .1
SERVICE_ADDRESS = "203.0.113.1"  # RFC 5737 TEST-NET-3, on the internet loopback
WAN_IFACE, WAN_PEER = "wan0", "wan1"
VPN_IFACE, VPN_PEER = "vpn0", "vpn1"
TCP_PORT = 9999
UDP_PORT = 9998
DNS_PORT = 53
ROOT = Path(__file__).resolve().parents[2]


class NetbedError(RuntimeError):
    """A test-bed command failed."""


@dataclass
class Netbed:
    """Two network namespaces joined by two veth links.

    ::

        host ──wan0/wan1── internet
        host ──vpn0/vpn1── internet

    ``host`` is the machine under test: its only default route is the WAN
    link, and the VPN link exists for pyvpn's routing tables to use.
    ``internet`` owns ``SERVICE_ADDRESS`` on its loopback so one destination is
    reachable over either link; the TCP echo, UDP echo and DNS responder in
    ``services()`` report the source address they observed, which identifies
    the egress interface.

    No network state outside these namespaces is changed. Test code still runs
    as root in the host mount namespace: the namespaces are a network
    boundary, not a sandbox. Both are removed on teardown, including when the
    build fails half way.
    """

    tag: str
    # Routes removed by ``down()``, keyed by interface, restored by ``up()``.
    _saved_routes: dict[str, list[str]] = field(default_factory=dict, repr=False)

    @property
    def host(self) -> str:
        return f"{PREFIX}{self.tag}-host"

    @property
    def internet(self) -> str:
        return f"{PREFIX}{self.tag}-net"

    @classmethod
    def build(cls) -> Netbed:
        """Create the namespaces and links; raise ``NetbedError`` on failure."""
        for tool in ("ip", "ping"):
            if shutil.which(tool) is None:
                raise NetbedError(f"the test bed needs {tool!r} on PATH")
        bed = cls(uuid.uuid4().hex[:8])
        try:
            bed._create()
        except BaseException:
            with contextlib.suppress(Exception):
                bed.destroy()
            raise
        return bed

    def _create(self) -> None:
        self._ip("netns", "add", self.host)
        self._ip("netns", "add", self.internet)
        for ns in (self.host, self.internet):
            self.ip("link", "set", "lo", "up", ns=ns)
        for iface, peer, network in (
            (WAN_IFACE, WAN_PEER, WAN_NETWORK),
            (VPN_IFACE, VPN_PEER, VPN_NETWORK),
        ):
            self.ip(
                "link",
                "add",
                iface,
                "type",
                "veth",
                "peer",
                "name",
                peer,
                "netns",
                self.internet,
                ns=self.host,
            )
            for ns, link, host_octet in ((self.host, iface, "2"), (self.internet, peer, "1")):
                self.ip("addr", "add", f"{network}.{host_octet}/30", "dev", link, ns=ns)
                self.ip("link", "set", link, "up", ns=ns)
        # One address reachable over both links, so tests can compare egress.
        self.ip("addr", "add", f"{SERVICE_ADDRESS}/32", "dev", "lo", ns=self.internet)
        # The WAN is the only default path until a policy routes via the VPN.
        self.ip(
            "route",
            "add",
            "default",
            "via",
            f"{WAN_NETWORK}.1",
            "dev",
            WAN_IFACE,
            ns=self.host,
        )

    def ip(
        self, *args: str, ns: str | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Run ``ip [-n ns] args`` (links, addresses, routes, rules)."""
        argv = ["ip", *(["-n", ns] if ns else []), *args]
        return self._call(argv, check=check)

    def run(
        self,
        argv: Sequence[str],
        *,
        ns: str | None = None,
        check: bool = True,
        timeout: float = 20.0,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run a program, optionally inside ``ns`` via ``ip netns exec``."""
        command = ["ip", "netns", "exec", ns, *argv] if ns else list(argv)
        return self._call(command, check=check, timeout=timeout, cwd=cwd)

    @contextlib.contextmanager
    def services(self, *, dns_port: int = DNS_PORT) -> Iterator[Services]:
        """Start the internet-side echo servers; stop them on exit."""
        work = Path(tempfile.mkdtemp(prefix="pyvpn-tb-svc-"))
        try:
            ready, log, diagnostics = work / "ready", work / "log.jsonl", work / "worker.log"
            log.touch()
            with diagnostics.open("w", encoding="utf-8") as output:
                process = subprocess.Popen(
                    [
                        "ip",
                        "netns",
                        "exec",
                        self.internet,
                        sys.executable,
                        "-m",
                        "tests.integration.services",
                        "serve",
                        str(ready),
                        str(log),
                        SERVICE_ADDRESS,
                        str(TCP_PORT),
                        str(UDP_PORT),
                        str(dns_port),
                    ],
                    cwd=ROOT,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                )
                try:
                    deadline = time.monotonic() + 10.0
                    while not ready.exists():
                        if process.poll() is not None:
                            detail = diagnostics.read_text(encoding="utf-8").strip()
                            raise NetbedError(f"the internet services exited early: {detail}")
                        if time.monotonic() > deadline:
                            raise NetbedError("the internet services did not become ready")
                        time.sleep(0.05)
                    yield Services(log, process.pid)
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def tcp_echo(self, *, timeout: float = 5.0) -> str:
        """Source address the echo server saw for a TCP connection."""
        return self._probe("tcp", TCP_PORT, timeout)

    def udp_echo(self, *, timeout: float = 5.0) -> str:
        """Source address the echo server saw for a UDP datagram."""
        return self._probe("udp", UDP_PORT, timeout)

    def dns_query(
        self, name: str = "example.test", *, port: int = DNS_PORT, timeout: float = 5.0
    ) -> str:
        """Address in the A record the responder returns for ``name``."""
        result = self.run(
            [
                sys.executable,
                "-m",
                "tests.integration.services",
                "query",
                SERVICE_ADDRESS,
                name,
                str(port),
                str(timeout),
            ],
            ns=self.host,
            check=False,
            timeout=timeout + 10.0,
            cwd=ROOT,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise NetbedError(f"DNS query failed: {detail}")
        return result.stdout.strip()

    def _probe(self, kind: str, port: int, timeout: float) -> str:
        result = self.run(
            [
                sys.executable,
                "-m",
                "tests.integration.services",
                "probe",
                kind,
                SERVICE_ADDRESS,
                str(port),
                str(timeout),
            ],
            ns=self.host,
            check=False,
            timeout=timeout + 10.0,
            cwd=ROOT,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise NetbedError(f"{kind} probe failed: {detail}")
        return result.stdout.strip()

    def up(self, link: str) -> None:
        """Bring a link back up and restore the routes ``down`` removed."""
        iface = self._iface(link)
        self.ip("link", "set", iface, "up", ns=self.host)
        for route in self._saved_routes.pop(iface, []):
            self.ip("route", "replace", *route.split(), ns=self.host, check=False)

    def down(self, link: str) -> None:
        """Take a link down; the kernel drops its routes, ``up`` puts them back."""
        iface = self._iface(link)
        self._saved_routes[iface] = self._routes_via(iface)
        self.ip("link", "set", iface, "down", ns=self.host)

    def _iface(self, link: str) -> str:
        iface = {"wan": WAN_IFACE, "vpn": VPN_IFACE}.get(link)
        if iface is None:
            raise ValueError(f"unknown link {link!r}; use 'wan' or 'vpn'")
        return iface

    def _routes_via(self, iface: str) -> list[str]:
        """Static routes through ``iface``, which an admin-down removes."""
        routes = []
        for line in self.ip("route", "show", ns=self.host).stdout.splitlines():
            tokens = line.split()
            if "proto" in tokens and tokens[tokens.index("proto") + 1] == "kernel":
                continue
            if f"dev {iface}" in line:
                routes.append(line)
        return routes

    def namespaces(self) -> set[str]:
        """Names currently registered in ``/run/netns``."""
        names = set()
        for line in self._ip("netns", "list").stdout.splitlines():
            fields = line.split()
            if fields:
                names.add(fields[0])
        return names

    def destroy(self) -> None:
        """Delete both namespaces; raise if either survives.

        Safe to call twice: deleting an absent namespace is not an error.
        """
        errors, remaining = [], set()
        for ns in (self.host, self.internet):
            result = self._ip("netns", "delete", ns, check=False)
            if result.returncode != 0:
                errors.append(result.stderr.strip() or f"ip netns delete {ns} failed")
        remaining = {self.host, self.internet} & self.namespaces()
        if remaining:
            detail = "; ".join(errors) or "still registered"
            raise NetbedError(f"could not remove {sorted(remaining)}: {detail}")

    def _ip(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self._call(["ip", *args], check=check)

    def _call(
        self,
        argv: Sequence[str],
        *,
        check: bool,
        timeout: float = 20.0,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=timeout, check=False, cwd=cwd
        )
        if check and result.returncode != 0:
            raise NetbedError(f"{' '.join(argv)} failed: {result.stderr.strip()}")
        return result


@dataclass
class Services:
    """The echo servers running in the internet namespace."""

    log_path: Path
    pid: int

    @property
    def directory(self) -> Path:
        """The throwaway directory holding the log and the worker output."""
        return self.log_path.parent

    def observed(self) -> list[dict[str, object]]:
        """Every echo the servers answered, oldest first."""
        text = self.log_path.read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line]

    def peers(self, kind: str | None = None) -> list[str]:
        """Source addresses seen for ``"tcp"``, ``"udp"``, or both."""
        return [
            str(item["peer"]) for item in self.observed() if kind is None or item["kind"] == kind
        ]
