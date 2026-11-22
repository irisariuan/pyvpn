"""Route apply against a fake netlink (pure)."""

from __future__ import annotations

from dataclasses import replace

from pyvpn.config.models import LeakSettings
from pyvpn.constants import policy_cgroup, policy_mark, policy_rule_pref, policy_table
from pyvpn.routing.apply import RouteManager
from pyvpn.routing.plan import RoutePlan, Rule, build_route_plan
from pyvpn.state import AppBinding, PolicyPlan, RoutingPlan
from tests.routing._fakes import FakeNetlink


def policy(pid: int = 1, **kw: object) -> PolicyPlan:
    base: dict[str, object] = {
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
        "dns_stub_port": None,
    }
    base.update(kw)
    return PolicyPlan(**base)  # type: ignore[arg-type]


def plan(*policies: PolicyPlan) -> RoutePlan:
    return build_route_plan(RoutingPlan(policies))


def state(nl: FakeNetlink) -> RoutePlan:
    return RoutePlan(tuple(sorted(nl.rules(), key=repr)), tuple(sorted(nl.routes(), key=repr)))


def normalized(p: RoutePlan) -> RoutePlan:
    return RoutePlan(tuple(sorted(p.rules, key=repr)), tuple(sorted(p.routes, key=repr)))


def test_sync_installs_plan_and_is_idempotent() -> None:
    nl = FakeNetlink()
    want = plan(policy())
    RouteManager(nl).sync(want)
    assert state(nl) == normalized(want)

    nl.log.clear()
    RouteManager(nl).sync(want)
    assert nl.log == []


def test_guard_route_exists_before_rule_points_at_table() -> None:
    nl = FakeNetlink()
    RouteManager(nl).install(plan(policy()))
    for version in (4, 6):
        rule_at = nl.log.index(f"rule add v{version} 1001")
        assert nl.log.index(f"route replace v{version} 1001 unreachable") < rule_at
        assert nl.log.index(f"route replace v{version} 1001 unicast") < rule_at


def test_target_switch_replaces_device_in_place() -> None:
    nl = FakeNetlink()
    mgr = RouteManager(nl)
    mgr.sync(plan(policy()))
    nl.log.clear()
    mgr.sync(plan(policy(interface="tun0")))
    assert nl.log == ["route replace v4 1001 unicast", "route replace v6 1001 unicast"]
    assert {r.interface for r in nl.routes() if r.kind == "unicast"} == {"tun0"}


def test_kill_switch_keeps_rule_and_drops_device_route() -> None:
    nl = FakeNetlink()
    mgr = RouteManager(nl)
    mgr.sync(plan(policy()))
    mgr.sync(plan(policy(route="unreachable", interface=None)))
    assert {r.kind for r in nl.routes()} == {"unreachable"}
    assert len(nl.rules()) == 2


def test_prune_removes_dropped_policies_rule_before_its_table() -> None:
    nl = FakeNetlink()
    mgr = RouteManager(nl)
    mgr.sync(plan(policy(1), policy(2)))
    nl.log.clear()
    mgr.sync(plan(policy(1)))
    assert all(t.endswith("1002") or "1002 " in t for t in nl.log)
    last_rule = max(i for i, e in enumerate(nl.log) if e.startswith("rule del"))
    first_route = min(i for i, e in enumerate(nl.log) if e.startswith("route del"))
    assert last_rule < first_route
    assert {r.table for r in nl.routes()} == {1001}


def test_main_fallback_removes_ipv4_rule_and_table() -> None:
    nl = FakeNetlink()
    mgr = RouteManager(nl)
    mgr.sync(plan(policy()))
    mgr.sync(plan(policy(route="main", interface=None)))
    assert nl.rules() == [] and nl.routes() == []


def test_foreign_rules_and_routes_survive() -> None:
    nl = FakeNetlink()
    foreign_pref = Rule(4, 5201, 0x1, 0xFF, 200)  # our priority, someone else's table
    foreign_table = Rule(4, 100, 0xCA6C, 0xFFFFFFFF, 1001)  # our table, other priority
    nl._rules += [foreign_pref, foreign_table]
    mgr = RouteManager(nl)
    mgr.sync(plan(policy()))
    mgr.teardown()
    assert nl.rules() == [foreign_pref, foreign_table]
    assert nl.routes() == []


def test_teardown_removes_leftovers_from_a_previous_daemon() -> None:
    nl = FakeNetlink()
    RouteManager(nl).sync(plan(policy(1), policy(7)))
    fresh = RouteManager(nl)
    fresh.sync(plan(policy(1)))
    assert {r.table for r in nl.rules()} == {1001}
    fresh.teardown()
    assert nl.rules() == [] and nl.routes() == []


def test_ipv6_route_follows_leak_setting() -> None:
    nl = FakeNetlink()
    RouteManager(nl).sync(plan(replace(policy(), leak=LeakSettings(ipv6="off"))))
    assert {r.version for r in nl.rules()} == {4}
