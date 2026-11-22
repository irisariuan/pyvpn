"""Egress capture through the internet-side echo services (PLAN.md §8)."""

from __future__ import annotations

import contextlib
import os

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

        assert services.peers("tcp") == [VPN_PEER]
        assert services.peers("udp") == [VPN_PEER]


def test_dns_is_answered_and_names_the_wan_source(netbed: Netbed) -> None:
    with netbed.services() as services:
        assert netbed.dns_query("example.test") == ANSWER_ADDRESS

        assert services.peers("dns") == [WAN_PEER]


def test_dns_over_the_vpn_link_names_the_vpn_source(netbed: Netbed) -> None:
    with netbed.services() as services, route_via_vpn(netbed):
        assert netbed.dns_query("example.test") == ANSWER_ADDRESS

        assert services.peers("dns") == [VPN_PEER]


def test_a_downed_vpn_link_falls_back_to_the_wan(netbed: Netbed) -> None:
    # Downing a device makes the kernel drop its routes, so this is ordinary
    # fallback, not policy: the policy-level "block" test belongs to stage 4.
    with netbed.services() as services, route_via_vpn(netbed):
        assert netbed.tcp_echo() == VPN_PEER

        netbed.down("vpn")
        assert netbed.tcp_echo() == WAN_PEER
        assert services.peers("tcp") == [VPN_PEER, WAN_PEER]


def test_without_any_route_the_probe_fails_and_logs_nothing(netbed: Netbed) -> None:
    # What a fail-closed policy looks like from here: the probe cannot send,
    # and the server records no observation.
    with netbed.services() as services:
        netbed.down("wan")
        netbed.down("vpn")
        try:
            before = services.observed()
            with pytest.raises(NetbedError):
                netbed.tcp_echo(timeout=1.0)
            assert services.observed() == before
        finally:
            netbed.up("wan")
            netbed.up("vpn")


def test_services_stops_the_worker_and_removes_its_directory(netbed: Netbed) -> None:
    with netbed.services() as services:
        pid, directory = services.pid, services.directory
        assert directory.is_dir()
        assert netbed.tcp_echo() == WAN_PEER

    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert not directory.exists()
