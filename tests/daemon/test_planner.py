from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

from pyvpn.config.models import Config
from pyvpn.constants import FWMARK_BASE, dns_stub_port
from pyvpn.daemon.planner import build_plan, choose_target
from pyvpn.state import AppBinding, DestSet, TargetStatus
from tests.fakes.targets import down, up

JP = up("jp", "wg-jp")
NL = up("nl", "tun0", ifindex=11)
OFFICE = up("office", "wlan1", ifindex=12)


def plan_of(config: Config, *statuses: TargetStatus, **kw: object):  # type: ignore[no-untyped-def]
    return build_plan(
        config,
        {s.name: s for s in statuses},
        kw.get("bindings", {}),  # type: ignore[arg-type]
        kw.get("dests", {}),  # type: ignore[arg-type]
    )


def test_first_usable_target_wins(config: Config) -> None:
    p = plan_of(config, JP, NL).policies[0]
    assert (p.route, p.interface, p.target) == ("dev", "wg-jp", "jp")


def test_falls_back_to_next_target(config: Config) -> None:
    p = plan_of(config, down("jp", "wg-jp"), NL).policies[0]
    assert (p.route, p.interface, p.target) == ("dev", "tun0", "nl")


def test_no_target_on_down_default_uses_main(config: Config) -> None:
    p = plan_of(config, down("jp"), down("nl")).policies[0]
    assert (p.route, p.interface, p.target) == ("main", None, None)


def test_no_target_on_down_block_is_unreachable(config: Config) -> None:
    p = plan_of(config, down("nl")).policies[1]
    assert (p.route, p.interface) == ("unreachable", None)


def test_unknown_status_counts_as_down(config: Config) -> None:
    plan = plan_of(config)
    assert [p.route for p in plan.policies] == ["main", "unreachable", "main"]


def test_usable_without_interface_counts_as_down(config: Config) -> None:
    weird = TargetStatus("nl", None, None, True)
    assert plan_of(config, weird).policies[1].route == "unreachable"


def test_choose_target_respects_policy_order(config: Config) -> None:
    pol = config.policies[0]
    assert choose_target(pol, {"nl": NL, "jp": JP}) == ("jp", JP)


def test_numbering(config: Config) -> None:
    plan = plan_of(config)
    assert [p.policy_id for p in plan.policies] == [1, 2, 3]
    assert [p.table for p in plan.policies] == [1001, 1002, 1003]
    assert [p.rule_pref for p in plan.policies] == [5201, 5202, 5203]
    assert [p.mark for p in plan.policies] == [FWMARK_BASE | i for i in (1, 2, 3)]


def test_dns_stub_port_only_with_dns_via_target(config: Config) -> None:
    plan = plan_of(config)
    assert [p.dns_stub_port for p in plan.policies] == [dns_stub_port(1), dns_stub_port(2), None]


def test_dests_none_without_domains_and_empty_set_with(config: Config) -> None:
    plan = plan_of(config)
    assert plan.policies[0].dests is None
    assert plan.policies[2].dests == DestSet(3)  # nothing routed until DNS fills it


def test_dests_are_passed_through(config: Config) -> None:
    d = DestSet(3, frozenset({IPv4Network("10.20.0.0/16")}))
    assert plan_of(config, dests={3: d}).policies[2].dests == d


def test_default_binding(config: Config) -> None:
    plan = plan_of(config)
    assert plan.policies[0].apps == AppBinding(1)
    assert plan.policies[2].apps == AppBinding(3, any_process=True)


def test_binding_is_used(config: Config) -> None:
    b = AppBinding(1, cgroup_paths=("pyvpn.slice/p-1",))
    assert plan_of(config, bindings={1: b}).policies[0].apps == b


def test_gateway_from_status_then_config(config: Config) -> None:
    assert plan_of(config, OFFICE).policies[2].gateway == IPv4Address("192.168.8.1")
    learned = up("office", "wlan1", gateway=IPv4Address("10.0.0.1"))
    assert plan_of(config, learned).policies[2].gateway == IPv4Address("10.0.0.1")


def test_plan_is_deterministic(config: Config) -> None:
    assert plan_of(config, JP, NL) == plan_of(config, JP, NL)
