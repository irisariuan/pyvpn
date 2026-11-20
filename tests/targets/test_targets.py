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
    address_is_routable,
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
    target = Target(name="vpn", interface="tun*")
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
            gateways=(_address("10.0.0.1"),),
        ),
    )

    status = status_for_target(target, snapshots)

    assert status.name == "japan"
    assert status.interface == "wg-jp"
    assert status.ifindex == 42
    assert status.usable
    assert status.gateway == _address("10.0.0.1")


def test_auto_gateway_loss_makes_broadcast_target_unusable() -> None:
    target = Target(name="office", interface="wlan1", gateway="auto")
    snapshot = InterfaceSnapshot("wlan1", 42, True, (_address("192.0.2.10"),))

    status = status_for_target(target, (snapshot,))

    assert not status.usable
    assert status.gateway is None


def test_device_only_target_remains_usable_without_gateway() -> None:
    target = Target(name="vpn", interface="wg0")
    snapshot = InterfaceSnapshot("wg0", 42, True, (_address("10.0.0.2"),))

    status = status_for_target(target, (snapshot,))

    assert status.usable
    assert status.gateway is None


def test_status_for_missing_interface_is_down() -> None:
    target = Target(name="japan", interface="wg-*")
    status = status_for_target(target, ())
    assert status.interface is None
    assert status.ifindex is None
    assert not status.usable


def test_unsupported_probe_only_marks_its_target_unusable() -> None:
    probe_target = Target(name="vpn", interface="tun0", probe=True)
    healthy_target = Target(name="office", interface="eth0")
    snapshots = (
        InterfaceSnapshot("tun0", 1, True, (_address("10.0.0.2"),)),
        InterfaceSnapshot("eth0", 2, True, (_address("192.0.2.2"),)),
    )

    class OneSnapshotReader:
        async def events(self) -> AsyncIterator[tuple[InterfaceSnapshot, ...]]:
            yield snapshots

    statuses = NetlinkTargetWatcher(
        (probe_target, healthy_target),
        OneSnapshotReader(),
    )

    async def collect() -> list[dict[str, TargetStatus]]:
        return [status async for status in statuses.statuses()]

    (status_map,) = asyncio.run(collect())
    assert not status_map["vpn"].usable
    assert status_map["office"].usable


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
    assert snapshots[0].gateways == (_address("192.0.2.2"), _address("2001:db8::1"))


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


def test_link_local_and_tentative_addresses_do_not_make_a_target_usable() -> None:
    link = {"index": 3, "flags": 0x10041, "attrs": [("IFLA_IFNAME", "wlan1")]}

    def addr(value: str, scope: int = 0, flags: int = 0, **attrs: int) -> dict[str, object]:
        return {
            "index": 3,
            "scope": scope,
            "flags": flags,
            "attrs": [("IFA_ADDRESS", value), *attrs.items()],
        }

    assert not address_is_routable(addr("fe80::1", scope=253))
    assert not address_is_routable(addr("169.254.3.4", scope=253))
    assert not address_is_routable(addr("2001:db8::5", flags=0x40))  # tentative
    assert not address_is_routable(addr("2001:db8::5", IFA_FLAGS=0x08))  # dadfailed
    assert address_is_routable(addr("192.0.2.10"))

    target = Target(name="office", interface="wlan1")
    carrier_only = _snapshots_from_messages([link], [addr("fe80::1", scope=253)], [])
    assert carrier_only[0].addresses == ()
    assert not status_for_target(target, carrier_only).usable

    leased = _snapshots_from_messages([link], [addr("fe80::1", scope=253), addr("192.0.2.10")], [])
    assert leased[0].addresses == (_address("192.0.2.10"),)
    assert status_for_target(target, leased).usable


def test_watchers_skip_bursts_that_change_no_target() -> None:
    target = Target(name="vpn", interface="tun0")
    up = (InterfaceSnapshot("tun0", 1, True, (_address("10.0.0.2"),)),)
    other = (*up, InterfaceSnapshot("eth0", 2, True, (_address("192.0.2.1"),)))

    async def snapshots() -> AsyncIterator[tuple[InterfaceSnapshot, ...]]:
        for item in (up, up, other, up):  # e.g. pyvpn's own route changes
            yield item

    class FakeReader:
        def events(self) -> AsyncIterator[tuple[InterfaceSnapshot, ...]]:
            return snapshots()

    async def collect() -> tuple[int, int]:
        a = [s async for s in NetlinkTargetWatcher((target,), FakeReader()).statuses()]
        b = [s async for s in TargetWatcher((target,), snapshots()).statuses()]
        return len(a), len(b)

    assert asyncio.run(collect()) == (1, 1)


def test_probe_target_is_unusable_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    target = Target(name="probed", interface="wg0", probe=True)
    snapshot = InterfaceSnapshot("wg0", 42, True, (_address("10.0.0.2"),))
    assert not status_for_target(target, (snapshot,)).usable
    assert not status_for_target(target, (snapshot,)).usable
    assert caplog.text.count("probe: true, which is not supported yet") == 1
