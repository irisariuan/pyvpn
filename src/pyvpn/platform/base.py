"""Platform backend protocol (Phase 0 contract). Linux implementation: stream C."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from pyvpn.state import DestSet, RoutingPlan


@dataclass(frozen=True)
class Capabilities:
    transparent: bool = False
    user: bool = False
    proxy: bool = False
    per_app_dns: bool = False


class Backend(Protocol):
    @property
    def capabilities(self) -> Capabilities: ...

    async def apply(self, plan: RoutingPlan) -> None:
        """Replace the whole installed state with ``plan``, atomically.

        Raises on failure; the previously installed state must then be intact.
        """

    async def add_to_set(self, dests: DestSet) -> None:
        """Add addresses to a policy's destination set without a full apply."""

    async def teardown(self) -> None:
        """Remove everything pyvpn installed."""
