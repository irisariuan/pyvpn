from __future__ import annotations

from pyvpn.state import DestSet


class FakeRuleMatcher:
    def __init__(
        self, domains: dict[str, int] | None = None, static: list[DestSet] | None = None
    ) -> None:
        self.domains = domains or {}
        self.static = static or []

    def match(self, domain: str) -> int | None:
        return self.domains.get(domain)

    def static_sets(self) -> list[DestSet]:
        return list(self.static)
