"""Install ``build_route_plan`` output with netlink, idempotently.

pyvpn owns rules that match a reserved policy slot's priority, mark, mask and
table, and the default routes in its reserved tables. Other rules and more
specific routes are left alone.

Applying is split so the backend can order it around the nft transaction:

* ``install`` only adds or swaps entries: every desired table gets its
  unreachable guard and its device route (``replace`` swaps the device in
  place, at a fixed metric), then the desired rules are added. A rule is never
  added before its table has the guard, so marked traffic cannot fall through.
* ``prune`` removes what the plan no longer wants: stale routes in the
  desired tables (e.g. the device route when the policy becomes a kill
  switch), stale rules, then routes of tables no rule points to.

Netlink calls sit behind ``RouteNetlink`` so unit tests run against a fake.
"""

from __future__ import annotations

import errno
import socket
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Protocol

from pyvpn.constants import MAX_POLICIES, TABLE_BASE, policy_mark, policy_rule_pref
from pyvpn.routing.plan import POLICY_MARK_MASK, DefaultRoute, IPVersion, RoutePlan, Rule

PROC_SYS = Path("/proc/sys")
_RTN_UNICAST = 1
_RTN_UNREACHABLE = 7


def ipv6_available(proc_sys: Path = PROC_SYS) -> bool:
    """False on a kernel booted with ``ipv6.disable=1`` (no IPv6 stack).

    ``disable_ipv6=1`` alone keeps the stack, and IPv6 rules still work.
    """
    return (proc_sys / "net/ipv6").is_dir()


def owns_rule(rule: Rule) -> bool:
    policy_id = rule.table - TABLE_BASE
    return (
        1 <= policy_id <= MAX_POLICIES
        and rule.priority == policy_rule_pref(policy_id)
        and rule.mark == policy_mark(policy_id)
        and rule.mask == POLICY_MARK_MASK
    )


def owns_table(table: int) -> bool:
    return TABLE_BASE < table <= TABLE_BASE + MAX_POLICIES


class RouteNetlink(Protocol):
    """The few netlink operations route apply needs."""

    def rules(self) -> list[Rule]:
        """Fwmark rules for both address families."""

    def routes(self) -> list[DefaultRoute]:
        """Default routes (both families) in tables pyvpn owns."""

    def add_rule(self, rule: Rule) -> None:
        """Add ``rule``; an identical existing rule is not an error."""

    def delete_rule(self, rule: Rule) -> None:
        """Delete ``rule``; a missing rule is not an error."""

    def replace_route(self, route: DefaultRoute) -> None: ...

    def delete_route(self, route: DefaultRoute) -> None:
        """Delete ``route``; a missing route is not an error."""


def _route_key(route: DefaultRoute) -> tuple[int, int, int]:
    return (route.version, route.table, route.metric)


class RouteManager:
    def __init__(self, netlink: RouteNetlink) -> None:
        self.netlink = netlink

    def snapshot(self) -> RoutePlan:
        """Read the currently installed managed entries, including after a restart."""
        return RoutePlan(
            tuple(rule for rule in self.netlink.rules() if owns_rule(rule)),
            tuple(self.netlink.routes()),
        )

    def install(self, plan: RoutePlan) -> None:
        nl = self.netlink
        current = set(nl.routes())
        # Guards first, then device routes, so a table is never empty once
        # a rule can point at it.
        for route in sorted(plan.routes, key=lambda r: r.kind != "unreachable"):
            if route not in current:
                nl.replace_route(route)
        existing = set(nl.rules())
        for rule in plan.rules:
            if rule not in existing:
                nl.add_rule(rule)

    def prune(self, plan: RoutePlan) -> None:
        nl = self.netlink
        wanted_routes = set(plan.routes)
        wanted_keys = {_route_key(r) for r in plan.routes}
        wanted_tables = {(r.version, r.table) for r in plan.rules}
        routes = nl.routes()
        # Stale routes in tables still in use; a route whose key is wanted
        # was already swapped by ``replace`` in ``install``.
        for route in routes:
            if (route.version, route.table) in wanted_tables and _route_key(
                route
            ) not in wanted_keys:
                nl.delete_route(route)
        wanted_rules = set(plan.rules)
        for rule in nl.rules():
            if owns_rule(rule) and rule not in wanted_rules:
                nl.delete_rule(rule)
        for route in routes:
            if (route.version, route.table) not in wanted_tables and route not in wanted_routes:
                nl.delete_route(route)

    def sync(self, plan: RoutePlan) -> None:
        self.install(plan)
        self.prune(plan)

    def teardown(self) -> None:
        self.prune(RoutePlan((), ()))


# --- pyroute2 ------------------------------------------------------------------


def _family(version: IPVersion) -> int:
    return socket.AF_INET if version == 4 else socket.AF_INET6


def _attr(msg: Any, name: str) -> Any:
    getter = getattr(msg, "get_attr", None)
    if getter is not None:
        return getter(name)
    for key, value in msg.get("attrs", ()):
        if key == name:
            return value
    return None


def _ignore(err: Exception, *codes: int) -> None:
    """Swallow a netlink error with one of ``codes``; re-raise anything else.

    pyroute2 raises ``NetlinkError`` (not an ``OSError``) carrying ``code``.
    """
    code = getattr(err, "code", None) or getattr(err, "errno", None)
    if code not in codes:
        raise err


class Pyroute2Netlink:
    """``RouteNetlink`` on a pyroute2 ``IPRoute`` socket (opened lazily)."""

    def __init__(self, ipr: Any = None, *, proc_sys: Path = PROC_SYS) -> None:
        self._ipr = ipr
        self._proc_sys = proc_sys

    def _versions(self) -> tuple[IPVersion, ...]:
        return (4, 6) if ipv6_available(self._proc_sys) else (4,)

    @property
    def ipr(self) -> Any:
        if self._ipr is None:
            from pyroute2 import IPRoute

            self._ipr = IPRoute()
        return self._ipr

    def close(self) -> None:
        if self._ipr is not None:
            self._ipr.close()
            self._ipr = None

    def rules(self) -> list[Rule]:
        out: list[Rule] = []
        for version in self._versions():
            for msg in self.ipr.get_rules(family=_family(version)):
                mark = _attr(msg, "FRA_FWMARK")
                mask = _attr(msg, "FRA_FWMASK")
                prio = _attr(msg, "FRA_PRIORITY")
                table = _attr(msg, "FRA_TABLE") or msg.get("table")
                if mark is None or prio is None or table is None:
                    continue
                if mask is None:
                    mask = 0xFFFF_FFFF
                out.append(Rule(version, int(prio), int(mark), int(mask), int(table)))
        return out

    def routes(self) -> list[DefaultRoute]:
        out: list[DefaultRoute] = []
        names: dict[int, str | None] = {}
        for version in self._versions():
            for msg in self.ipr.get_routes(family=_family(version), table=None):
                table = _attr(msg, "RTA_TABLE") or msg.get("table")
                if table is None or not owns_table(int(table)) or msg.get("dst_len") != 0:
                    continue
                metric = int(_attr(msg, "RTA_PRIORITY") or 0)
                kind = msg.get("type")
                if kind == _RTN_UNREACHABLE:
                    out.append(DefaultRoute(version, int(table), metric, "unreachable"))
                    continue
                if kind != _RTN_UNICAST:
                    continue
                oif = _attr(msg, "RTA_OIF")
                name = None
                if oif is not None:
                    if oif not in names:
                        links = self.ipr.get_links(oif)
                        names[oif] = links[0].get_attr("IFLA_IFNAME") if links else None
                    name = names[oif]
                gw = _attr(msg, "RTA_GATEWAY")
                gateway = ip_address(gw) if gw else None
                out.append(DefaultRoute(version, int(table), metric, "unicast", name, gateway))
        return out

    def _rule_args(self, rule: Rule) -> dict[str, Any]:
        return {
            "family": _family(rule.version),
            "priority": rule.priority,
            "fwmark": rule.mark,
            "fwmask": rule.mask,
            "table": rule.table,
        }

    def add_rule(self, rule: Rule) -> None:
        try:
            self.ipr.rule("add", **self._rule_args(rule))
        except Exception as e:
            _ignore(e, errno.EEXIST)

    def delete_rule(self, rule: Rule) -> None:
        try:
            self.ipr.rule("del", **self._rule_args(rule))
        except Exception as e:
            _ignore(e, errno.ENOENT, errno.ESRCH)

    def _route_args(self, route: DefaultRoute) -> dict[str, Any]:
        args: dict[str, Any] = {
            "family": _family(route.version),
            "dst": "0.0.0.0/0" if route.version == 4 else "::/0",
            "table": route.table,
            "priority": route.metric,
        }
        if route.kind == "unreachable":
            args["type"] = "unreachable"
            return args
        args["type"] = "unicast"
        if route.interface is not None:
            idx = self.ipr.link_lookup(ifname=route.interface)
            if not idx:
                raise OSError(errno.ENODEV, f"no such interface {route.interface!r}")
            args["oif"] = idx[0]
        if route.gateway is not None:
            args["gateway"] = str(route.gateway)
        return args

    def replace_route(self, route: DefaultRoute) -> None:
        self.ipr.route("replace", **self._route_args(route))

    def delete_route(self, route: DefaultRoute) -> None:
        args = self._route_args(route) if route.kind == "unreachable" else _delete_args(route)
        try:
            self.ipr.route("del", **args)
        except Exception as e:
            _ignore(e, errno.ENOENT, errno.ESRCH)


def _delete_args(route: DefaultRoute) -> dict[str, Any]:
    # The device may already be gone; table, dst and metric identify the route.
    return {
        "family": _family(route.version),
        "dst": "0.0.0.0/0" if route.version == 4 else "::/0",
        "table": route.table,
        "priority": route.metric,
    }
