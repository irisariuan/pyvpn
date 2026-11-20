from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator, Iterable

import pytest

from pyvpn.config.models import Target
from pyvpn.platform.linux.netlink import (
    NetlinkTargetWatcher,
    _default_gateways,
    _snapshots_from_messages,
    link_is_up,
    parse_address,
    parse_gateway,
)
from pyvpn.state import TargetStatus
from pyvpn.targets import (
    InterfaceSnapshot,
    TargetWatcher,
    resolve_interface,
    resolve_interfaces,
    status_for_target,
)
from pyvpn.targets.probes import parse_probe


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(value)


def test_resolve_interface_exact_and_glob() -> None:
    names = ("eth0", "wg-a", "wg-b")
    assert resolve_interface("eth0", names) == "eth0"
    assert resolve_interface("wg*", names) == "wg-a"
    assert resolve_interface("missing*", names) is None
    assert resolve_interfaces("wg*", names) == ("wg-a", "wg-b")


def test_pattern_prefers_first_usable_interface_in_sorted_order() -> None:
    target = Target(name="vpn", interface="tun*", gateway="auto")
    snapshots = (
        InterfaceSnapshot("tun1", 11, True, (_address("10.0.1.2"),)),
        InterfaceSnapshot("tun0", 10, False, (_address("10.0.0.2"),)),
    )

    status = status_for_target(target, snapshots)

    assert status.interface == "tun1"
    assert status.ifindex == 11
    assert status.usable


def test_pattern_falls_back_to_first_match_when_none_are_usable() -> None:
    target = Target(name="vpn", interface="tun*")
    snapshots = (
        InterfaceSnapshot("tun1", 11, False, (_address("10.0.1.2"),)),
        InterfaceSnapshot("tun0", 10, False, (_address("10.0.0.2"),)),
    )

    status = status_for_target(target, snapshots)

    assert status.interface == "tun0"
    assert status.ifindex == 10
    assert not status.usable


def test_status_for_target_resolves_auto_gateway() -> None:
    target = Target(name="japan", interface="wg-*", gateway="auto")
    snapshots = (
        InterfaceSnapshot(
            name="wg-jp",
            ifindex=42,
            up=True,
            addresses=(_address("10.0.0.2"),),
            gateway=_address("10.0.0.1"),
        ),
    )

    status = status_for_target(target, snapshots)

    assert status.name == "japan"
    assert status.interface == "wg-jp"
    assert status.ifindex == 42
    assert status.usable
    assert status.gateway == _address("10.0.0.1")


def test_status_for_missing_interface_is_down() -> None:
    target = Target(name="japan", interface="wg-*")
    status = status_for_target(target, ())
    assert status.interface is None
    assert status.ifindex is None
    assert not status.usable


def test_probe_configuration_is_not_silently_ignored() -> None:
    target = Target(name="vpn", interface="tun0", probe=True)

    with pytest.raises(NotImplementedError, match=r"probing.*not supported"):
        status_for_target(target, ())


def test_link_requires_carrier_but_accepts_unknown_operstate() -> None:
    assert not link_is_up({"flags": 0x1, "attrs": (("IFLA_OPERSTATE", "DOWN"),)})
    assert link_is_up({"flags": 0x1, "attrs": (("IFLA_OPERSTATE", "UNKNOWN"),)})
    assert link_is_up({"flags": 0x10001})


def test_default_gateway_uses_main_table_default_and_lowest_metric_per_family() -> None:
    routes = (
        {
            "dst_len": 24,
            "table": 254,
            "oif": 10,
            "attrs": (("RTA_GATEWAY", "192.0.2.9"), ("RTA_PRIORITY", 1)),
        },
        {
            "dst_len": 0,
            "table": 100,
            "oif": 10,
            "attrs": (("RTA_GATEWAY", "192.0.2.8"), ("RTA_PRIORITY", 1)),
        },
        {
            "dst_len": 0,
            "table": 254,
            "oif": 10,
            "attrs": (("RTA_GATEWAY", "192.0.2.1"), ("RTA_PRIORITY", 200)),
        },
        {
            "dst_len": 0,
            "table": 254,
            "oif": 10,
            "attrs": (("RTA_GATEWAY", "192.0.2.2"), ("RTA_PRIORITY", 100)),
        },
        {
            "dst_len": 0,
            "table": 254,
            "oif": 10,
            "attrs": (("RTA_GATEWAY", "2001:db8::1"), ("RTA_PRIORITY", 50)),
        },
    )

    assert _default_gateways(routes) == {10: {4: _address("192.0.2.2"), 6: _address("2001:db8::1")}}

    snapshots = _snapshots_from_messages(
        ({"index": 10, "flags": 0x10001, "attrs": (("IFLA_IFNAME", "eth0"),)},),
        (
            {"index": 10, "attrs": (("IFA_LOCAL", "192.0.2.10"),)},
            {"index": 10, "attrs": (("IFA_LOCAL", "2001:db8::10"),)},
        ),
        routes,
    )
    assert snapshots[0].gateway == _address("192.0.2.2")


def test_parse_address_prefers_local_over_peer_address() -> None:
    message = {
        "attrs": (
            ("IFA_ADDRESS", "198.51.100.1"),
            ("IFA_LOCAL", "198.51.100.2"),
        )
    }
    assert parse_address(message) == _address("198.51.100.2")


def test_probe_endpoint_requires_ip_literal() -> None:
    assert parse_probe("1.1.1.1:443") == ("1.1.1.1", 443)
    assert parse_probe("[2001:db8::1]:443") == ("2001:db8::1", 443)
    with pytest.raises(ValueError, match="IP literals"):
        parse_probe("example.com:443")


def test_parse_netlink_values() -> None:
    assert parse_address({"address": "10.2.3.4"}) == _address("10.2.3.4")
    assert parse_address({"attrs": (("IFA_ADDRESS", "2001:db8::1"),)}) == _address("2001:db8::1")
    assert parse_gateway({"attrs": (("RTA_GATEWAY", "192.0.2.1"),)}) == _address("192.0.2.1")


def test_target_watcher_emits_status_for_each_event() -> None:
    target = Target(name="vpn", interface="tun0")

    async def events() -> AsyncIterator[Iterable[InterfaceSnapshot]]:
        yield (InterfaceSnapshot("tun0", 1, False),)
        yield (InterfaceSnapshot("tun0", 1, True, (_address("10.0.0.2"),)),)

    async def collect() -> list[dict[str, TargetStatus]]:
        return [status async for status in TargetWatcher((target,), events()).statuses()]

    statuses = asyncio.run(collect())
    assert len(statuses) == 2
    assert not statuses[0]["vpn"].usable
    assert statuses[1]["vpn"].usable


def test_netlink_target_watcher_emits_reader_events() -> None:
    target = Target(name="vpn", interface="tun0")

    class FakeReader:
        async def events(self) -> AsyncIterator[tuple[InterfaceSnapshot, ...]]:
            yield (InterfaceSnapshot("tun0", 1, False),)
            yield (InterfaceSnapshot("tun0", 1, True, (_address("10.0.0.2"),)),)

    async def collect() -> list[dict[str, TargetStatus]]:
        return [status async for status in NetlinkTargetWatcher((target,), FakeReader()).statuses()]

    statuses = asyncio.run(collect())
    assert len(statuses) == 2
    assert not statuses[0]["vpn"].usable
    assert statuses[1]["vpn"].usable
