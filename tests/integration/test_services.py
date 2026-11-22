"""Egress capture through the internet-side echo services (PLAN.md §8)."""

from __future__ import annotations

import contextlib

import pytest

from tests.integration.netbed import (
    SERVICE_ADDRESS,
    VPN_IFACE,
    VPN_NETWORK,
    WAN_NETWORK,
    Netbed,
    NetbedError,
)
from tests.integration.services import ANSWER_ADDRESS

pytestmark = pytest.mark.integration

WAN_PEER = f"{WAN_NETWORK}.2"
VPN_PEER = f"{VPN_NETWORK}.2"


@contextlib.contextmanager
def route_via_vpn(netbed: Netbed):
    """Send exactly SERVICE_ADDRESS over the VPN link while inside the block."""
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
        yield
    finally:
        netbed.ip("route", "del", f"{SERVICE_ADDRESS}/32", ns=netbed.host, check=False)


def test_tcp_and_udp_egress_identify_the_wan_link(netbed: Netbed) -> None:
    with netbed.services() as services:
        assert netbed.tcp_echo() == WAN_PEER
        assert netbed.udp_echo() == WAN_PEER

        assert services.peers("tcp") == [WAN_PEER]
        assert services.peers("udp") == [WAN_PEER]


def test_the_same_destination_identifies_the_vpn_link(netbed: Netbed) -> None:
    with netbed.services() as services, route_via_vpn(netbed):
        assert netbed.tcp_echo() == VPN_PEER
        assert netbed.udp_echo() == VPN_PEER

        assert services.peers() == [VPN_PEER, VPN_PEER]


def test_dns_is_answered_and_names_the_wan_source(netbed: Netbed) -> None:
    with netbed.services() as services:
        assert netbed.dns_query("example.test") == ANSWER_ADDRESS

        assert services.peers("dns") == [WAN_PEER]


def test_dns_over_the_vpn_link_names_the_vpn_source(netbed: Netbed) -> None:
    with netbed.services() as services, route_via_vpn(netbed):
        assert netbed.dns_query("example.test") == ANSWER_ADDRESS

        assert services.peers("dns") == [VPN_PEER]


def test_a_downed_link_is_no_longer_used_for_egress(netbed: Netbed) -> None:
    with netbed.services() as services, route_via_vpn(netbed):
        assert netbed.tcp_echo() == VPN_PEER
        seen_over_vpn = services.peers().count(VPN_PEER)

        netbed.down("vpn")
        # the bed cannot drop packets; it can only make the link unusable, so
        # the probe either falls back to the WAN or fails outright
        try:
            peer_after_down: str | None = netbed.tcp_echo(timeout=2.0)
        except NetbedError:
            peer_after_down = None
        assert peer_after_down != VPN_PEER
        assert services.peers().count(VPN_PEER) == seen_over_vpn

        netbed.up("vpn")
        netbed.ip(
            "route",
            "replace",
            f"{SERVICE_ADDRESS}/32",
            "via",
            f"{VPN_NETWORK}.1",
            "dev",
            VPN_IFACE,
            ns=netbed.host,
        )
        assert netbed.tcp_echo() == VPN_PEER
