from dataclasses import replace
from ipaddress import ip_address

import pytest

from pyvpn.config.models import LeakSettings
from pyvpn.constants import policy_mark, policy_rule_pref, policy_table
from pyvpn.routing.plan import DefaultRoute, Rule, build_route_plan
from pyvpn.state import AppBinding, IPAddress, PolicyPlan, RoutingPlan


def policy(policy_id: int = 1) -> PolicyPlan:
    return PolicyPlan(
        policy_id=policy_id,
        mark=policy_mark(policy_id),
        table=policy_table(policy_id),
        rule_pref=policy_rule_pref(policy_id),
        route="dev",
        interface="wg-jp",
        gateway=None,
        apps=AppBinding(policy_id, cgroup_paths=(f"pyvpn.slice/p-{policy_id}",)),
        dests=None,
        leak=LeakSettings(),
        dns_stub_port=None,
    )


def test_active_target_keeps_a_device_independent_unreachable_default() -> None:
    result = build_route_plan(RoutingPlan((policy(),)))

    assert result.rules == (
        Rule(4, 5201, 0x5059_0001, 0xFFFF_007F, 1001),
        Rule(6, 5201, 0x5059_0001, 0xFFFF_007F, 1001),
    )
    assert result.routes == (
        DefaultRoute(4, 1001, 32760, "unreachable"),
        DefaultRoute(4, 1001, 100, "unicast", "wg-jp"),
        DefaultRoute(6, 1001, 32760, "unreachable"),
        DefaultRoute(6, 1001, 100, "unicast", "wg-jp"),
    )


@pytest.mark.parametrize("gateway", [ip_address("192.0.2.1"), ip_address("2001:db8::1")])
def test_explicit_gateway_routes_only_its_family(gateway: IPAddress) -> None:
    result = build_route_plan(RoutingPlan((replace(policy(), gateway=gateway),)))

    assert [(r.version, r.kind) for r in result.routes if r.gateway is None] == [
        (4, "unreachable"),
        (6, "unreachable"),
    ]
    (target,) = [r for r in result.routes if r.kind == "unicast"]
    assert (target.version, target.interface, target.gateway) == (gateway.version, "wg-jp", gateway)


def test_kill_switch_guards_both_families_when_target_is_absent() -> None:
    active = policy()
    blocked = replace(active, route="unreachable", interface=None, leak=LeakSettings(ipv6="off"))
    result = build_route_plan(RoutingPlan((blocked,)))

    assert result.rules == build_route_plan(RoutingPlan((active,))).rules
    assert result.routes == (
        DefaultRoute(4, 1001, 32760, "unreachable"),
        DefaultRoute(6, 1001, 32760, "unreachable"),
    )


def test_default_fallback_only_installs_a_rule_for_explicit_ipv6_block() -> None:
    fallback = replace(policy(), route="main", interface=None)
    result = build_route_plan(RoutingPlan((fallback,)))
    assert result.rules == result.routes == ()

    ipv6_block = replace(fallback, leak=LeakSettings(ipv6="block"))
    result = build_route_plan(RoutingPlan((ipv6_block,)))
    assert result.rules == (Rule(6, 5201, 0x5059_0001, 0xFFFF_007F, 1001),)
    assert result.routes == (DefaultRoute(6, 1001, 32760, "unreachable"),)


def test_ipv6_off_omits_ipv6_entries_while_target_is_up() -> None:
    active = replace(policy(), leak=LeakSettings(ipv6="off"))
    result = build_route_plan(RoutingPlan((active,)))

    assert [rule.version for rule in result.rules] == [4]
    assert [route.version for route in result.routes] == [4, 4]


def test_rule_matches_its_policy_id_and_ignores_unreserved_bits() -> None:
    result = build_route_plan(RoutingPlan((policy(1), policy(2))))
    first, second = (rule for rule in result.rules if rule.version == 4)

    assert (first.mark | 0x0000_0100) & first.mask == first.mark
    assert second.mark & first.mask != first.mark


@pytest.mark.parametrize(
    ("invalid", "message"),
    [
        (replace(policy(), table=254), "reserved slot"),
        (replace(policy(), apps=AppBinding(2)), "belongs to another policy"),
        (replace(policy(), interface=None), "requires an interface"),
    ],
)
def test_rejects_inconsistent_plan(invalid: PolicyPlan, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_route_plan(RoutingPlan((invalid,)))


def test_rejects_duplicate_policy_slots() -> None:
    with pytest.raises(ValueError, match="duplicate policy 1"):
        build_route_plan(RoutingPlan((policy(), policy())))
