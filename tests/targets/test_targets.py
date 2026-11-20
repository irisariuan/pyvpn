from __future__ import annotations

import ipaddress

from pyvpn.config.models import Target
from pyvpn.platform.linux.netlink import parse_address, parse_gateway
from pyvpn.targets import (
    InterfaceSnapshot,
    resolve_interface,
    resolve_interfaces,
    status_for_target,
)
from pyvpn.targets.probes import parse_probe


def test_resolve_interface_exact_and_glob() -> None:
    names = ("eth0", "wg-a", "wg-b")
    assert resolve_interface("eth0", names) == "eth0"
    assert resolve_interface("wg*", names) == "wg-a"
    assert resolve_interface("missing*", names) is None
    assert resolve_interfaces("wg*", names) == ("wg-a", "wg-b")


def test_status_for_target_resolves_auto_gateway() -> None:
    target = Target(name="japan", interface="wg-*", gateway="auto", probe=False)
    snapshots = (
        InterfaceSnapshot(
            name="wg-jp",
            ifindex=42,
            up=True,
            addresses=(ipaddress.ip_address("10.0.0.2"),),
            gateway=ipaddress.ip_address("10.0.0.1"),
        ),
    )

    status = status_for_target(target, snapshots)

    assert status.name == "japan"
    assert status.interface == "wg-jp"
    assert status.ifindex == 42
    assert status.usable
    assert status.gateway == ipaddress.ip_address("10.0.0.1")


def test_status_for_missing_interface_is_down() -> None:
    target = Target(name="japan", interface="wg-*")
    status = status_for_target(target, ())
    assert status.interface is None
    assert status.ifindex is None
    assert not status.usable


def test_parse_probe_and_netlink_values() -> None:
    assert parse_probe("1.1.1.1:443") == ("1.1.1.1", 443)
    assert parse_address({"address": "10.2.3.4"}) == ipaddress.ip_address("10.2.3.4")
    assert parse_address({"attrs": (("IFA_ADDRESS", "2001:db8::1"),)}) == ipaddress.ip_address(
        "2001:db8::1"
    )
    assert parse_gateway({"attrs": (("RTA_GATEWAY", "192.0.2.1"),)}) == ipaddress.ip_address(
        "192.0.2.1"
    )
