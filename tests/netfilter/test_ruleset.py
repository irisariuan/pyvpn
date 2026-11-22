"""Golden nft output for every PolicyPlan variant (pure, no nft calls).

Regenerate after an intended change with ``PYVPN_UPDATE_GOLDEN=1 pytest
tests/netfilter`` and review the diff.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from ipaddress import IPv4Network, IPv6Network, ip_address
from pathlib import Path
from typing import Any

import pytest

from pyvpn.config.models import LeakSettings
from pyvpn.constants import (
    FWMARK_MASK,
    MAX_POLICIES,
    dns_stub_port,
    excluded_cgroup,
    policy_cgroup,
    policy_mark,
    policy_rule_pref,
    policy_table,
)
from pyvpn.netfilter import build_ruleset, build_set_update, build_teardown
from pyvpn.netfilter.render import render
from pyvpn.netfilter.ruleset import build_route_guard
from pyvpn.routing.plan import POLICY_MARK_MASK
from pyvpn.state import AppBinding, DestSet, PolicyPlan, RoutingPlan

GOLDEN = Path(__file__).parent / "golden"
UPDATE = os.environ.get("PYVPN_UPDATE_GOLDEN") == "1"


def policy(pid: int = 1, **kw: Any) -> PolicyPlan:
    base: dict[str, Any] = {
        "policy_id": pid,
        "mark": policy_mark(pid),
        "table": policy_table(pid),
        "rule_pref": policy_rule_pref(pid),
        "route": "dev",
        "interface": "wg-jp",
        "gateway": None,
        "apps": AppBinding(pid, cgroup_paths=(policy_cgroup(pid),)),
        "dests": None,
        "leak": LeakSettings(),
        "dns_stub_port": dns_stub_port(pid),
    }
    base.update(kw)
    return PolicyPlan(**base)


def dests(pid: int = 1) -> DestSet:
    return DestSet(
        pid,
        frozenset({IPv4Network("203.0.113.0/24"), IPv4Network("198.51.100.7/32")}),
        frozenset({IPv6Network("2001:db8::/32"), IPv6Network("2001:db8:1::5/128")}),
    )


def drops(pid: int = 1) -> DestSet:
    return DestSet(
        pid,
        frozenset({IPv4Network("192.0.2.0/24"), IPv4Network("198.18.0.9/32")}),
        frozenset({IPv6Network("2001:db8:dead::/48")}),
        drop=True,
    )


VARIANTS: dict[str, RoutingPlan] = {
    "empty": RoutingPlan(),
    "dev_cgroup": RoutingPlan((policy(),)),
    "dev_gateway": RoutingPlan((policy(interface="wlan1", gateway=ip_address("192.168.8.1")),)),
    "dev_uids": RoutingPlan((policy(apps=AppBinding(1, uids=(1001,))),)),
    "dev_cgroups_and_uids": RoutingPlan(
        (
            policy(
                apps=AppBinding(
                    1,
                    cgroup_paths=("pyvpn.slice/p-1", "/system.slice/transmission.service"),
                    uids=(1002, 1001),
                )
            ),
        )
    ),
    "dev_dests": RoutingPlan((policy(dests=dests()),)),
    "dev_dests_empty": RoutingPlan((policy(dests=DestSet(1)),)),
    "any_process_dests": RoutingPlan(
        (policy(apps=AppBinding(1, any_process=True), dests=dests()),)
    ),
    "unbound": RoutingPlan((policy(apps=AppBinding(1)),)),
    "unreachable": RoutingPlan((policy(route="unreachable", interface=None),)),
    "unreachable_dests": RoutingPlan(
        (
            policy(
                route="unreachable",
                interface=None,
                apps=AppBinding(1, any_process=True),
                dests=dests(),
            ),
        )
    ),
    "main": RoutingPlan((policy(route="main", interface=None),)),
    "no_dns_stub": RoutingPlan((policy(dns_stub_port=None),)),
    "block_dot": RoutingPlan((policy(leak=LeakSettings(block_dot=True)),)),
    "block_doh": RoutingPlan((policy(leak=LeakSettings(block_doh=True)),)),
    "block_quic": RoutingPlan((policy(leak=LeakSettings(block_quic=True)),)),
    "ipv6_block": RoutingPlan((policy(leak=LeakSettings(ipv6="block")),)),
    "ipv6_off": RoutingPlan((policy(leak=LeakSettings(ipv6="off")),)),
    "all_leaks_dests": RoutingPlan(
        (
            policy(
                dests=dests(),
                leak=LeakSettings(block_dot=True, block_doh=True, block_quic=True, ipv6="block"),
            ),
        )
    ),
    "dev_drops": RoutingPlan((policy(dests=dests(), drops=drops()),)),
    "dev_drops_empty": RoutingPlan((policy(dests=DestSet(1), drops=DestSet(1, drop=True)),)),
    "any_process_drops": RoutingPlan(
        (policy(apps=AppBinding(1, any_process=True), dests=dests(), drops=drops()),)
    ),
    "unreachable_drops": RoutingPlan(
        (
            policy(
                route="unreachable",
                interface=None,
                apps=AppBinding(1, any_process=True),
                dests=DestSet(1),
                drops=drops(),
            ),
        )
    ),
    "multi": RoutingPlan(
        (
            policy(1),
            policy(2, route="unreachable", interface=None, dns_stub_port=None),
            policy(3, route="main", interface=None, apps=AppBinding(3, uids=(1003,))),
            policy(4, interface="tun0", apps=AppBinding(4, any_process=True), dests=dests(4)),
        )
    ),
}


def _check_golden(name: str, actual: str) -> None:
    path = GOLDEN / name
    if UPDATE:
        path.write_text(actual)
    assert path.exists(), f"missing golden {path.name}; run with PYVPN_UPDATE_GOLDEN=1"
    assert actual == path.read_text(), f"{path.name} changed; review and regenerate"


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_ruleset_matches_golden_json(name: str) -> None:
    doc = build_ruleset(VARIANTS[name])
    _check_golden(f"{name}.json", json.dumps(doc, indent=2, sort_keys=True) + "\n")


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_rendered_script_matches_golden(name: str) -> None:
    _check_golden(f"{name}.nft", render(build_ruleset(VARIANTS[name])))


def test_set_update_and_teardown_match_golden() -> None:
    update = build_set_update(dests(4))
    _check_golden("set_update.json", json.dumps(update, indent=2, sort_keys=True) + "\n")
    _check_golden("set_update.nft", render(update))
    _check_golden("teardown.nft", render(build_teardown()))


def test_drop_set_update_matches_golden() -> None:
    update = build_set_update(drops(2))
    _check_golden("set_update_drop.json", json.dumps(update, indent=2, sort_keys=True) + "\n")
    _check_golden("set_update_drop.nft", render(update))
    names = [cmd["add"]["element"]["name"] for cmd in update["nftables"]]
    assert names == ["p2_drop_v4", "p2_drop_v6"]


def test_set_update_skips_empty_families() -> None:
    only_v4 = DestSet(2, frozenset({IPv4Network("192.0.2.0/24")}))
    (cmd,) = build_set_update(only_v4)["nftables"]
    assert cmd["add"]["element"]["name"] == "p2_v4"
    assert build_set_update(DestSet(2)) == {"nftables": []}


# --- properties every variant must keep ------------------------------------------


def _rules(doc: dict[str, Any], chain: str) -> list[list[dict[str, Any]]]:
    return [
        c["add"]["rule"]["expr"]
        for c in doc["nftables"]
        if "rule" in c.get("add", {}) and c["add"]["rule"]["chain"] == chain
    ]


def _mangles(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        e["mangle"]
        for c in doc["nftables"]
        if "rule" in c.get("add", {})
        for e in c["add"]["rule"]["expr"]
        if "mangle" in e
    ]


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_marks_keep_bits_owned_by_other_software(name: str) -> None:
    for mangle in _mangles(build_ruleset(VARIANTS[name])):
        keep, mark = mangle["value"]["|"]
        assert keep["&"] == [mangle["key"], ~POLICY_MARK_MASK & 0xFFFF_FFFF]
        assert mark & ~POLICY_MARK_MASK == 0


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_table_is_replaced_in_one_transaction(name: str) -> None:
    cmds = build_ruleset(VARIANTS[name])["nftables"]
    table = {"family": "inet", "name": "pyvpn"}
    assert cmds[:3] == [
        {"add": {"table": table}},
        {"delete": {"table": table}},
        {"add": {"table": table}},
    ]


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_kill_switch_never_marks_traffic(name: str) -> None:
    doc = build_ruleset(VARIANTS[name])
    for p in VARIANTS[name].policies:
        if p.route != "unreachable":
            continue
        route_chain = _rules(doc, f"p{p.policy_id}_route")
        assert route_chain[-1] == [{"reject": {"type": "icmpx", "expr": "admin-prohibited"}}]
        assert not any("mangle" in e for rule in route_chain for e in rule)
        restore = [r for r in _rules(doc, "output") if r[0].get("match", {}).get("right") == p.mark]
        assert restore and restore[0][-1] == {
            "reject": {"type": "icmpx", "expr": "admin-prohibited"}
        }


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_socket_marked_dns_is_never_redirected(name: str) -> None:
    first = _rules(build_ruleset(VARIANTS[name]), "dns")[0]
    assert first == [
        {
            "match": {
                "op": "==",
                "left": {"&": [{"meta": {"key": "mark"}}, FWMARK_MASK]},
                "right": 0x5059_0000,
            }
        },
        {"return": None},
    ]


def test_lan_exemption_comes_before_any_mark() -> None:
    out = _rules(build_ruleset(VARIANTS["multi"]), "output")
    lan = [i for i, r in enumerate(out) if r[0]["match"]["right"] in ("@lan_v4", "@lan_v6")]
    marks = [
        i
        for i, r in enumerate(out)
        if any("mangle" in e or ("jump" in e and e["jump"]["target"] != "check_cgroup") for e in r)
    ]
    assert len(lan) == 2 and max(lan) < min(marks)
    assert all(out[i][-1] == {"accept": None} for i in lan)


def test_unknown_policy_cgroups_are_rejected_before_anything_else() -> None:
    doc = build_ruleset(VARIANTS["multi"])
    out = _rules(doc, "output")
    socket = {"socket": {"key": "cgroupv2", "level": 2}}
    assert out[0] == [
        {
            "match": {
                "op": "==",
                "left": {"socket": {"key": "cgroupv2", "level": 1}},
                "right": "pyvpn.slice",
            }
        },
        {"jump": {"target": "check_cgroup"}},
    ]
    assert _rules(doc, "check_cgroup") == [
        [{"match": {"op": "==", "left": socket, "right": "pyvpn.slice/p-1"}}, {"return": None}],
        [{"match": {"op": "==", "left": socket, "right": "pyvpn.slice/p-2"}}, {"return": None}],
        [{"reject": {"type": "icmpx", "expr": "admin-prohibited"}}],
    ]
    assert not _rules(build_ruleset(VARIANTS["dev_uids"]), "check_cgroup")


def test_cgroup_guard_uses_bounded_rules_for_all_policy_slots() -> None:
    slots = range(1, MAX_POLICIES + 1)
    doc = build_ruleset(RoutingPlan(tuple(policy(i) for i in slots)))
    *allowed, rejected = _rules(doc, "check_cgroup")
    assert len(allowed) == MAX_POLICIES
    assert {rule[0]["match"]["right"] for rule in allowed} == {policy_cgroup(i) for i in slots}
    assert all(len(rule) == 2 and rule[1] == {"return": None} for rule in allowed)
    assert "reject" in rejected[0]


def test_tracked_flows_go_through_current_leak_rules() -> None:
    doc = build_ruleset(VARIANTS["all_leaks_dests"])
    (tracked,) = [
        r
        for r in _rules(doc, "output")
        if r[0]["match"]["left"] == {"&": [{"ct": {"key": "mark"}}, POLICY_MARK_MASK]}
    ]
    assert tracked[0]["match"]["right"] == policy_mark(1)
    assert tracked[-1] == {"jump": {"target": "p1"}}
    policy_rules = _rules(doc, "p1")
    to_route = {"goto": {"target": "p1_route"}}
    assert all("reject" in rule[-1] for rule in policy_rules[:3])
    assert policy_rules[3] == [tracked[0], to_route]
    route_rules = _rules(doc, "p1_route")
    assert all("reject" in rule[-1] for rule in route_rules[:2])
    assert all("mangle" in expr for expr in route_rules[-1][:-1])


@pytest.mark.parametrize("name", ["dev_drops", "any_process_drops", "unreachable_drops"])
def test_drop_sets_reject_first_in_the_policy_chain(name: str) -> None:
    """Drop sets are checked before the conntrack mark and the route, so a
    connection opened before its address was learned is cut too."""
    doc = build_ruleset(VARIANTS[name])
    head = _rules(doc, "p1")
    for version, rule in zip((4, 6), head[:2], strict=True):
        proto = "ip" if version == 4 else "ip6"
        assert rule == [
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": proto, "field": "daddr"}},
                    "right": f"@p1_drop_v{version}",
                }
            },
            {"reject": {"type": "icmpx", "expr": "admin-prohibited"}},
        ]
    assert not any("reject" in r[-1] for r in head[2:])
    # The pyvpn sockets (DNS stub upstreams) are accepted before any policy
    # chain, so a drop rule never blocks the stub's own resolver.
    output = _rules(doc, "output")
    mark_accept = next(i for i, r in enumerate(output) if r[-1] == {"accept": None} and i > 1)
    first_jump = next(i for i, r in enumerate(output) if "jump" in r[-1] and "p1" in str(r[-1]))
    assert mark_accept < first_jump
    sets = {
        cmd["add"]["set"]["name"]: cmd["add"]["set"]
        for cmd in doc["nftables"]
        if "set" in cmd.get("add", {})
    }
    assert sets["p1_drop_v4"]["type"] == "ipv4_addr"
    assert sets["p1_drop_v6"]["type"] == "ipv6_addr"


def test_policies_without_drop_rules_have_no_drop_sets() -> None:
    for name, plan in VARIANTS.items():
        if any(p.drops is not None for p in plan.policies):
            continue
        assert "_drop_" not in json.dumps(build_ruleset(plan)), name


def test_temporary_route_guard_only_rejects_pyvpn_marks_after_classification() -> None:
    script = render(build_route_guard(enabled=True))
    assert "type filter hook output priority -80; policy accept;" in script
    assert (
        "add rule inet pyvpn_guard output meta mark & 0xffff0000 0x50590000 "
        "reject with icmpx type admin-prohibited\n"
    ) in script
    assert render(build_route_guard(enabled=False)) == (
        "add table inet pyvpn_guard\ndelete table inet pyvpn_guard\n"
    )


def test_masquerade_only_for_device_routes() -> None:
    masq = _rules(build_ruleset(VARIANTS["multi"]), "masq")
    assert [r[1]["match"]["right"] for r in masq] == ["wg-jp", "tun0"]


@pytest.mark.parametrize(
    ("name", "allowed_interfaces"),
    [
        ("dev_cgroup", {"ipv4": "wg-jp", "ipv6": "wg-jp"}),
        ("dev_gateway", {"ipv4": "wlan1", "ipv6": None}),
        ("ipv6_block", {"ipv4": "wg-jp", "ipv6": None}),
        ("ipv6_off", {"ipv4": "wg-jp"}),
        ("unreachable", {"ipv4": None, "ipv6": None}),
        ("main", {}),
    ],
)
def test_egress_drops_only_outside_each_managed_family(
    name: str, allowed_interfaces: dict[str, str | None]
) -> None:
    doc = build_ruleset(VARIANTS[name])
    actual = {}
    for mark, family, *verdict in _rules(doc, "egress"):
        assert mark["match"]["left"] == {"&": [{"meta": {"key": "mark"}}, POLICY_MARK_MASK]}
        assert mark["match"]["right"] == policy_mark(1)
        assert family["match"]["left"] == {"meta": {"key": "nfproto"}}
        assert verdict[-1] == {"drop": None}
        allowed = None
        if len(verdict) == 2:
            match = verdict[0]["match"]
            assert match["op"] == "!=" and match["left"] == {"meta": {"key": "oifname"}}
            allowed = match["right"]
        actual[family["match"]["right"]] = allowed
    assert actual == allowed_interfaces


def test_rejects_inconsistent_plans() -> None:
    with pytest.raises(ValueError, match="reserved slot"):
        build_ruleset(RoutingPlan((replace(policy(), mark=1),)))
    with pytest.raises(ValueError, match="duplicate policy 1"):
        build_ruleset(RoutingPlan((policy(), policy())))


def _dest_only(pid: int, *excluded: str) -> PolicyPlan:
    apps = AppBinding(pid, any_process=True, exclude_cgroup_paths=excluded)
    return policy(pid, apps=apps, dests=dests(pid))


def test_exclusion_cgroups_are_known_to_the_stale_cgroup_check() -> None:
    top, nested = excluded_cgroup([2]), excluded_cgroup([2], app_policy_id=1)
    plan = RoutingPlan((policy(1), _dest_only(2, top, nested, "system.slice/openvpn.service")))
    allowed = [r[0]["match"]["right"] for r in _rules(build_ruleset(plan), "check_cgroup")[:-1]]
    # Top-level x-<hex> is its own child; nested x-<hex> passes through p-1;
    # cgroups outside the slice never reach the check.
    assert allowed == ["pyvpn.slice/p-1", top]


def test_nested_exclusion_under_an_unknown_policy_cgroup_stays_rejected() -> None:
    nested = excluded_cgroup([2], app_policy_id=3)
    plan = RoutingPlan((policy(1), _dest_only(2, nested)))
    allowed = [r[0]["match"]["right"] for r in _rules(build_ruleset(plan), "check_cgroup")[:-1]]
    assert allowed == ["pyvpn.slice/p-1"]


def test_idle_exclusion_cgroups_are_governed_not_rejected() -> None:
    idle = excluded_cgroup([1, 2])
    doc = build_ruleset(
        RoutingPlan((policy(1),)),
        idle_exclusions=[idle, "pyvpn.slice/p-7", excluded_cgroup([2], app_policy_id=1)],
    )
    allowed = [r[0]["match"]["right"] for r in _rules(doc, "check_cgroup")[:-1]]
    assert allowed == ["pyvpn.slice/p-1", idle]
    assert idle not in render(build_ruleset(RoutingPlan((policy(1),))))
