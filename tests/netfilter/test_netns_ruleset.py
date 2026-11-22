"""Golden nft output for ``isolation: netns`` plans (pure, no nft calls).

Kept apart from ``test_ruleset.VARIANTS``: the kernel integration test loads
every variant there, and a namespace plan would create real namespaces.
Regenerate with ``PYVPN_UPDATE_GOLDEN=1 pytest tests/netfilter``.
"""

from __future__ import annotations

import json
from dataclasses import replace
from ipaddress import IPv4Network
from typing import Any

import pytest

from pyvpn.config.models import LeakSettings
from pyvpn.constants import NETNS_RANGE, netns_host_veth, netns_subnet
from pyvpn.netfilter import build_ruleset
from pyvpn.netfilter.render import render
from pyvpn.netfilter.ruleset import build_netns_ruleset, build_route_guard
from pyvpn.state import DestSet, PolicyPlan, RoutingPlan
from tests.netfilter.test_ruleset import _check_golden, _rules, policy


def isolated(pid: int = 1, **kw: Any) -> PolicyPlan:
    return replace(policy(pid), isolation="netns", **kw)


NETNS_VARIANTS: dict[str, tuple[RoutingPlan, tuple[str, ...]]] = {
    "netns_dev": (RoutingPlan((isolated(),)), ("wg-jp",)),
    "netns_block": (RoutingPlan((isolated(route="unreachable", interface=None),)), ()),
    "netns_main": (RoutingPlan((isolated(route="main", interface=None),)), ()),
    "netns_leaks": (
        RoutingPlan(
            (isolated(leak=LeakSettings(block_dot=True, block_doh=True, block_quic=True)),)
        ),
        ("wg-jp",),
    ),
    "netns_drops": (
        RoutingPlan(
            (
                isolated(
                    drops=DestSet(1, frozenset({IPv4Network("203.0.113.0/24")}), drop=True),
                ),
            )
        ),
        ("wg-jp",),
    ),
    "netns_mixed": (
        RoutingPlan((policy(1), isolated(2, interface="tun0"))),
        ("tun0", "wlan1"),
    ),
}


@pytest.mark.parametrize("name", sorted(NETNS_VARIANTS))
def test_netns_ruleset_matches_golden(name: str) -> None:
    plan, guard = NETNS_VARIANTS[name]
    doc = build_ruleset(plan, forwarding_guard=guard)
    _check_golden(f"{name}.json", json.dumps(doc, indent=2, sort_keys=True) + "\n")
    _check_golden(f"{name}.nft", render(doc))


def test_namespace_ruleset_matches_golden() -> None:
    _check_golden("netns_inside.nft", render(build_netns_ruleset()))


def test_plans_without_isolation_get_no_forward_chain() -> None:
    script = render(build_ruleset(RoutingPlan((policy(),))))
    assert "forward" not in script


def test_namespace_traffic_is_marked_before_routing() -> None:
    doc = build_ruleset(RoutingPlan((isolated(3),)))
    marks = [r for r in _rules(doc, "restore") if r[0].get("match", {}).get("right") == "pyvpn-h3"]
    assert len(marks) == 1
    assert [e["mangle"]["key"] for e in marks[0][1:]] == [
        {"meta": {"key": "mark"}},
        {"ct": {"key": "mark"}},
    ]


def test_kill_switch_namespace_rejects_everything_forwarded() -> None:
    doc = build_ruleset(RoutingPlan((isolated(route="unreachable", interface=None),)))
    chain = _rules(doc, "n1")
    assert "reject" in chain[-1][-1]
    assert not any("accept" in rule[-1] for rule in chain)
    assert not any(
        r[0].get("match", {}).get("left") == {"payload": {"protocol": "ip", "field": "saddr"}}
        for r in _rules(doc, "masq")
    )


def test_device_route_namespace_may_only_leave_via_target() -> None:
    chain = _rules(build_ruleset(RoutingPlan((isolated(interface="tun0"),))), "n1")
    assert chain[-2] == [
        {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "tun0"}},
        {"drop": None},
    ]
    assert chain[-1] == [{"accept": None}]


def test_forward_chain_drops_unknown_namespace_traffic_after_policy_jumps() -> None:
    doc = build_ruleset(RoutingPlan((isolated(2),)), forwarding_guard=("tun0",))
    forward = _rules(doc, "forward")
    jump = [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": netns_host_veth(2)}},
        {"jump": {"target": "n2"}},
    ]
    assert forward[0] == jump
    drops = [r for r in forward if r[-1] == {"drop": None}]
    rendered = render(
        {
            "nftables": [
                {
                    "add": {
                        "rule": {"family": "inet", "table": "pyvpn", "chain": "forward", "expr": r}
                    }
                }
                for r in drops
            ]
        }
    )
    assert f"ip saddr {NETNS_RANGE}" in rendered
    assert f"ip daddr {NETNS_RANGE}" in rendered
    assert 'meta iifname "tun0" drop' in rendered


def test_namespace_subnets_are_inside_the_range_and_distinct() -> None:
    subnets = {netns_subnet(i) for i in range(1, 100)}
    assert len(subnets) == 99
    assert all(s.subnet_of(NETNS_RANGE) for s in subnets)


def test_route_guard_also_stops_namespace_forwarding() -> None:
    script = render(build_route_guard(enabled=True))
    assert "add chain inet pyvpn_guard forward { type filter hook forward priority -80;" in script
    assert f"add rule inet pyvpn_guard forward ip saddr {NETNS_RANGE} drop\n" in script


def test_drop_rules_reject_namespace_traffic_before_it_can_be_accepted() -> None:
    plan = RoutingPlan((isolated(drops=DestSet(1, drop=True)),))
    chain = _rules(build_ruleset(plan), "n1")
    drop_at = next(i for i, r in enumerate(chain) if r[0]["match"].get("right") == "@p1_drop_v4")
    assert "reject" in chain[drop_at][-1]
    assert drop_at < next(i for i, r in enumerate(chain) if r == [{"accept": None}])
