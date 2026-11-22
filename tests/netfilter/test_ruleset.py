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
    dns_stub_port,
    policy_cgroup,
    policy_mark,
    policy_rule_pref,
    policy_table,
)
from pyvpn.netfilter import build_ruleset, build_set_update, build_teardown
from pyvpn.netfilter.render import render
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
    assert [r[-1] for r in out[:2]] == [{"accept": None}, {"accept": None}]
    assert [r[0]["match"]["right"] for r in out[:2]] == ["@lan_v4", "@lan_v6"]


def test_masquerade_only_for_device_routes() -> None:
    masq = _rules(build_ruleset(VARIANTS["multi"]), "masq")
    assert [r[1]["match"]["right"] for r in masq] == ["wg-jp", "tun0"]


def test_rejects_inconsistent_plans() -> None:
    with pytest.raises(ValueError, match="reserved slot"):
        build_ruleset(RoutingPlan((replace(policy(), mark=1),)))
    with pytest.raises(ValueError, match="duplicate policy 1"):
        build_ruleset(RoutingPlan((policy(), policy())))
