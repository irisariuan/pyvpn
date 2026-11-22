"""The network-namespace test bed from PLAN.md §8 (stream I)."""

from __future__ import annotations

import shutil
import subprocess
import uuid
from collections.abc import Sequence
from dataclasses import dataclass

PREFIX = "pyvpn-tb-"
WAN_NETWORK = "192.0.2"  # RFC 5737 TEST-NET-1: host .2, internet .1
VPN_NETWORK = "198.51.100"  # RFC 5737 TEST-NET-2: host .2, internet .1
SERVICE_ADDRESS = "203.0.113.1"  # RFC 5737 TEST-NET-3, on the internet loopback
WAN_IFACE, WAN_PEER = "wan0", "wan1"
VPN_IFACE, VPN_PEER = "vpn0", "vpn1"


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
    reachable over either link; a source address then identifies the egress
    interface (capture helpers arrive with the next stage).

    Nothing outside these namespaces is changed. Both are removed on
    teardown, including when the build fails half way.
    """

    tag: str
    # Whether this bed could turn off rp_filter for asymmetric replies.
    # /proc/sys is read-only in Docker, and some tests do not need it.
    rp_filter_off: bool = False

    @property
    def host(self) -> str:
        return f"{PREFIX}{self.tag}-host"

    @property
    def internet(self) -> str:
        return f"{PREFIX}{self.tag}-net"

    @classmethod
    def build(cls) -> Netbed:
        """Create the namespaces and links; raise ``NetbedError`` on failure."""
        for tool in ("ip", "sysctl"):
            if shutil.which(tool) is None:
                raise NetbedError(f"the test bed needs {tool!r} on PATH")
        bed = cls(uuid.uuid4().hex[:8])
        try:
            bed._create()
        except BaseException:
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
        # Replies to the service address arrive on the link the request left,
        # which is asymmetric for the per-link subnets; keep rp_filter out of
        # the way. Containers mount /proc/sys read-only: record whether it
        # worked and let tests that need it skip.
        self.rp_filter_off = self._disable_rp_filter()

    def _disable_rp_filter(self) -> bool:
        ok = True
        for ns in (self.host, self.internet):
            result = self.run(
                [
                    "sysctl",
                    "-qw",
                    "net.ipv4.conf.all.rp_filter=0",
                    "net.ipv4.conf.default.rp_filter=0",
                ],
                ns=ns,
                check=False,
            )
            ok = ok and result.returncode == 0
        return ok

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
    ) -> subprocess.CompletedProcess[str]:
        """Run a program, optionally inside ``ns`` via ``ip netns exec``."""
        command = ["ip", "netns", "exec", ns, *argv] if ns else list(argv)
        return self._call(command, check=check, timeout=timeout)

    def namespaces(self) -> set[str]:
        """Names currently registered in ``/run/netns``."""
        return {line.split()[0] for line in self._ip("netns", "list").stdout.splitlines() if line}

    def destroy(self) -> None:
        """Delete both namespaces; safe to call twice."""
        for ns in (self.host, self.internet):
            self._ip("netns", "delete", ns, check=False)

    def _ip(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self._call(["ip", *args], check=check)

    def _call(
        self, argv: Sequence[str], *, check: bool, timeout: float = 20.0
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=timeout, check=False
        )
        if check and result.returncode != 0:
            raise NetbedError(f"{' '.join(argv)} failed: {result.stderr.strip()}")
        return result
