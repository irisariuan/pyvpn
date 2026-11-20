"""Interfaces between workstreams (Phase 0 contract).

The daemon (B) depends only on these protocols; the real implementations come
from D (targets), E (apps), F (DNS) and G (rules), and ``tests/fakes/`` has a
fake of each.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from typing import Protocol

from pyvpn.config.models import AppGroup, Config, Policy
from pyvpn.state import AppBinding, DestSet, PolicyPlan, TargetStatus


class TargetWatcher(Protocol):
    """D. Yields the full status map (target name -> status) on every change."""

    def statuses(self) -> AsyncIterator[dict[str, TargetStatus]]: ...


class AppManager(Protocol):
    """E."""

    async def bind(
        self, policy_id: int, policy: Policy, groups: Sequence[AppGroup]
    ) -> AppBinding: ...

    async def unbind(self, policy_id: int) -> None: ...

    async def place_pid(self, pid: int, policy_id: int) -> None: ...

    def bindings(self) -> AsyncIterator[AppBinding]:
        """Yields a policy's binding whenever it changes."""
        ...


DestCallback = Callable[[DestSet], Awaitable[None]]


class DnsService(Protocol):
    """F. ``start`` is also called to update a running stub (new interface)."""

    async def start(self, plan: PolicyPlan) -> None: ...

    async def stop(self, policy_id: int) -> None: ...

    def on_answer(self, cb: DestCallback) -> None:
        """``cb`` must complete before the stub releases the answer."""


class RuleMatcher(Protocol):
    """G."""

    def match(self, domain: str) -> int | None: ...

    def static_sets(self) -> list[DestSet]: ...


RuleMatcherFactory = Callable[[Config], RuleMatcher]
