"""Self-tests for the network test bed itself (PLAN.md §8).

These prove the bed before any stream builds a policy test on top of it: both
namespaces and links exist and are up, the WAN is the only default path, one
destination is reachable over either link, teardown removes everything, and
the host's own namespace is untouched.
"""

from __future__ import annotations

import subprocess

import pytest

from tests.integration.netbed import (
    SERVICE_ADDRESS,
    VPN_IFACE,
    VPN_NETWORK,
    VPN_PEER,
    WAN_IFACE,
    WAN_NETWORK,
    WAN_PEER,
    Netbed,
    NetbedError,
)

pytestmark = pytest.mark.integration


def test_builds_two_namespaces_with_both_links(netbed: Netbed) -> None:
    assert {netbed.host, netbed.internet} <= netbed.namespaces()
    for iface, peer, network in (
        (WAN_IFACE, WAN_PEER, WAN_NETWORK),
        (VPN_IFACE, VPN_PEER, VPN_NETWORK),
    ):
        link = netbed.ip("-o", "link", "show", "dev", iface, ns=netbed.host).stdout
        assert "state UP" in link
        addrs = netbed.ip("-o", "addr", "show", "dev", peer, ns=netbed.internet).stdout
        assert f"{network}.1/30" in addrs


def test_wan_is_the_only_default_route(netbed: Netbed) -> None:
    routes = netbed.ip("route", "show", "default", ns=netbed.host).stdout
    assert "dev wan0" in routes
    assert "dev vpn0" not in routes


def test_each_link_reaches_its_peer(netbed: Netbed) -> None:
    for network in (WAN_NETWORK, VPN_NETWORK):
        # ping's exit status is the assertion; -W keeps a broken bed quick.
        netbed.run(["ping", "-c", "1", "-W", "1", f"{network}.1"], ns=netbed.host)


def test_service_address_answers_over_the_wan(netbed: Netbed) -> None:
    route = netbed.ip("route", "get", SERVICE_ADDRESS, ns=netbed.host).stdout
    assert "dev wan0" in route
    netbed.run(["ping", "-c", "1", "-W", "1", SERVICE_ADDRESS], ns=netbed.host)


def test_same_destination_reachable_over_the_vpn_link(netbed: Netbed) -> None:
    # A /32 beats the default route, so this is the VPN path to the same address.
    netbed.ip(
        "route",
        "add",
        f"{SERVICE_ADDRESS}/32",
        "via",
        f"{VPN_NETWORK}.1",
        "dev",
        VPN_IFACE,
        ns=netbed.host,
    )
    try:
        route = netbed.ip("route", "get", SERVICE_ADDRESS, ns=netbed.host).stdout
        assert f"dev {VPN_IFACE}" in route
        netbed.run(["ping", "-c", "1", "-W", "1", SERVICE_ADDRESS], ns=netbed.host)
    finally:
        netbed.ip("route", "del", f"{SERVICE_ADDRESS}/32", ns=netbed.host, check=False)


def test_destroy_removes_its_namespaces(netbed: Netbed) -> None:
    assert {netbed.host, netbed.internet} <= netbed.namespaces()

    netbed.destroy()
    assert not {netbed.host, netbed.internet} & netbed.namespaces()


def test_the_bed_leaves_the_root_namespace_alone(netbed: Netbed) -> None:
    namespaces, links = netbed.namespaces(), netbed.ip("-o", "link", "show").stdout

    other = Netbed.build()
    try:
        assert other.host in netbed.namespaces()
    finally:
        other.destroy()

    assert netbed.namespaces() == namespaces
    assert netbed.ip("-o", "link", "show").stdout == links
    assert other.host not in netbed.namespaces()


def test_destroy_reports_a_namespace_that_survives(netbed: Netbed, monkeypatch) -> None:
    def stuck(self: Netbed, *args: str, check: bool = True):
        return subprocess.CompletedProcess(["ip", *args], 1, "", "Device or resource busy")

    monkeypatch.setattr(Netbed, "_ip", stuck)
    monkeypatch.setattr(Netbed, "namespaces", lambda self: {self.host})
    with pytest.raises(NetbedError, match="could not remove"):
        netbed.destroy()
