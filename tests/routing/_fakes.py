"""In-memory ``RouteNetlink`` shared by route-apply and backend tests."""

from __future__ import annotations

from pyvpn.routing.plan import DefaultRoute, Rule


class FakeNetlink:
    """In-memory rules and routes; ``log`` records every mutating call."""

    def __init__(self, log: list[str] | None = None) -> None:
        self._rules: list[Rule] = []
        self._routes: dict[tuple[int, int, int], DefaultRoute] = {}
        self.log = [] if log is None else log
        self.fail_on: str | None = None

    def _record(self, entry: str) -> None:
        if self.fail_on and entry.startswith(self.fail_on):
            raise OSError(f"netlink: simulated failure on {entry}")
        self.log.append(entry)

    def rules(self) -> list[Rule]:
        return list(self._rules)

    def routes(self) -> list[DefaultRoute]:
        return list(self._routes.values())

    def add_rule(self, rule: Rule) -> None:
        self._record(f"rule add v{rule.version} {rule.table}")
        if rule not in self._rules:
            self._rules.append(rule)

    def delete_rule(self, rule: Rule) -> None:
        self._record(f"rule del v{rule.version} {rule.table}")
        if rule in self._rules:
            self._rules.remove(rule)

    def replace_route(self, route: DefaultRoute) -> None:
        self._record(f"route replace v{route.version} {route.table} {route.kind}")
        self._routes[(route.version, route.table, route.metric)] = route

    def delete_route(self, route: DefaultRoute) -> None:
        self._record(f"route del v{route.version} {route.table} {route.kind}")
        self._routes.pop((route.version, route.table, route.metric), None)
