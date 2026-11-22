"""End-to-end routing through the daemon on the test bed (PLAN.md §8, M1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.integration.daemon import daemon
from tests.integration.netbed import VPN_NETWORK, WAN_NETWORK, Netbed, NetbedError

pytestmark = pytest.mark.integration

WAN_PEER = f"{WAN_NETWORK}.2"
VPN_PEER = f"{VPN_NETWORK}.2"
POLICY_ID = 1


def test_placed_tcp_traffic_leaves_via_the_policy_target(netbed: Netbed, tmp_path: Path) -> None:
    with netbed.services() as services, daemon(netbed, tmp_path) as running:
        running.wait_route(POLICY_ID, "dev")

        assert running.probe("tcp") == VPN_PEER
        assert services.peers("tcp") == [VPN_PEER]


def test_placed_udp_traffic_leaves_via_the_policy_target(netbed: Netbed, tmp_path: Path) -> None:
    with netbed.services() as services, daemon(netbed, tmp_path) as running:
        running.wait_route(POLICY_ID, "dev")

        assert running.probe("udp") == VPN_PEER
        assert services.peers("udp") == [VPN_PEER]


def test_unplaced_traffic_keeps_the_wan_route(netbed: Netbed, tmp_path: Path) -> None:
    with netbed.services() as services, daemon(netbed, tmp_path) as running:
        running.wait_route(POLICY_ID, "dev")

        assert netbed.tcp_echo() == WAN_PEER
        assert running.probe("tcp") == VPN_PEER
        assert services.peers("tcp") == [WAN_PEER, VPN_PEER]


def test_kill_switch_drops_placed_traffic_after_the_target_goes_down(
    netbed: Netbed, tmp_path: Path
) -> None:
    with netbed.services() as services, daemon(netbed, tmp_path) as running:
        running.wait_route(POLICY_ID, "dev")
        assert running.probe("tcp") == VPN_PEER
        before = services.observed()

        netbed.down("vpn")
        running.wait_route(POLICY_ID, "unreachable")
        with pytest.raises(NetbedError):
            running.probe("tcp", timeout=1.0)
        assert services.observed() == before

        netbed.up("vpn")
        running.wait_route(POLICY_ID, "dev")
        assert running.probe("tcp") == VPN_PEER
