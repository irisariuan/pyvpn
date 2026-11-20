"""Reconcile loop: keep the installed state equal to the planned state.

Every input change (config, target statuses, app bindings, destination sets)
recomputes the plan under one lock and applies it if it differs from what is
installed. Applies are serialized, so the plan applied last always reflects
the latest inputs.

DNS answers take a fast path (``add_dests``): the addresses are recorded and
pushed with ``Backend.add_to_set`` under the same lock, so a concurrent full
apply can never drop them. If pushing fails the error propagates to the DNS
stub, which must answer SERVFAIL instead of releasing the reply.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import replace

from pyvpn.config.models import Config
from pyvpn.daemon.planner import build_plan
from pyvpn.platform.base import Backend
from pyvpn.services import DnsService
from pyvpn.state import AppBinding, DestSet, PolicyPlan, RoutingPlan, TargetStatus

log = logging.getLogger(__name__)

_DNS_FIELDS = ("route", "interface", "gateway", "leak", "dns_stub_port")


def _dns_changed(old: PolicyPlan | None, new: PolicyPlan) -> bool:
    return old is None or any(getattr(old, f) != getattr(new, f) for f in _DNS_FIELDS)


class Reconciler:
    def __init__(
        self,
        backend: Backend,
        dns: DnsService | None = None,
        *,
        retry_initial: float = 0.5,
        retry_max: float = 30.0,
    ) -> None:
        self._backend = backend
        self._dns = dns
        self._lock = asyncio.Lock()
        self._retry_initial = retry_initial
        self._retry_max = retry_max
        self._retry_delay = retry_initial
        self._retry_task: asyncio.Task[None] | None = None
        self._batch_depth = 0

        self.config: Config | None = None
        self.statuses: dict[str, TargetStatus] = {}
        self.bindings: dict[int, AppBinding] = {}
        self.static_dests: dict[int, DestSet] = {}
        self.dynamic_dests: dict[int, DestSet] = {}

        self.enabled = True
        self.applied: RoutingPlan | None = None
        self.last_error: str | None = None

    # --- inputs ---------------------------------------------------------------

    async def set_config(self, config: Config, static_sets: Iterable[DestSet] = ()) -> None:
        """Install a new config. Policy ids may shift, so per-id state is reset;
        callers rebind apps inside ``batch()`` to avoid an unbound window."""
        self.config = config
        self.bindings = {}
        self.dynamic_dests = {}
        self.static_dests = {}
        for s in static_sets:
            prev = self.static_dests.get(s.policy_id)
            self.static_dests[s.policy_id] = s if prev is None else prev | s
        await self.reconcile()

    async def update_targets(self, statuses: Mapping[str, TargetStatus]) -> None:
        self.statuses = dict(statuses)
        await self.reconcile()

    async def update_binding(self, binding: AppBinding) -> None:
        if self.config is None or not 1 <= binding.policy_id <= len(self.config.policies):
            log.warning("ignoring binding for unknown policy %d", binding.policy_id)
            return
        self.bindings[binding.policy_id] = binding
        await self.reconcile()

    async def add_dests(self, dests: DestSet) -> None:
        async with self._lock:
            prev = self.dynamic_dests.get(dests.policy_id)
            self.dynamic_dests[dests.policy_id] = dests if prev is None else prev | dests
            if not self.enabled or self.applied is None or self._batch_depth:
                return
            plans = list(self.applied.policies)
            for i, p in enumerate(plans):
                if p.policy_id == dests.policy_id and p.dests is not None:
                    await self._backend.add_to_set(dests)
                    plans[i] = replace(p, dests=p.dests | dests)
                    self.applied = RoutingPlan(tuple(plans))
                    return

    @contextlib.asynccontextmanager
    async def batch(self) -> AsyncIterator[None]:
        """Defer applying until the block exits (e.g. reload + rebind)."""
        self._batch_depth += 1
        try:
            yield
        finally:
            self._batch_depth -= 1
        if not self._batch_depth:
            await self.reconcile()

    # --- control --------------------------------------------------------------

    def plan(self) -> RoutingPlan | None:
        if self.config is None:
            return None
        dests: dict[int, DestSet] = {}
        for src in (self.static_dests, self.dynamic_dests):
            for pid, d in src.items():
                dests[pid] = d if pid not in dests else dests[pid] | d
        return build_plan(self.config, self.statuses, self.bindings, dests)

    async def reconcile(self) -> None:
        if self._batch_depth:
            return
        async with self._lock:
            await self._reconcile_locked()

    async def _reconcile_locked(self) -> None:
        if not self.enabled:
            return
        plan = self.plan()
        if plan is None or plan == self.applied:
            return
        try:
            await self._backend.apply(plan)
        except Exception as e:  # backend keeps the previous state on failure
            self.last_error = f"apply failed: {e}"
            log.exception("apply failed; retrying")
            self._schedule_retry()
            return
        old = self.applied
        self.applied = plan
        self.last_error = None
        self._retry_delay = self._retry_initial
        await self._sync_dns(old, plan)

    async def _sync_dns(self, old: RoutingPlan | None, new: RoutingPlan) -> None:
        if self._dns is None:
            return
        before = {p.policy_id: p for p in old.policies} if old else {}
        for p in new.policies:
            prev = before.pop(p.policy_id, None)
            try:
                if p.dns_stub_port is None:
                    if prev is not None and prev.dns_stub_port is not None:
                        await self._dns.stop(p.policy_id)
                elif _dns_changed(prev, p):
                    await self._dns.start(p)
            except Exception as e:
                self.last_error = f"dns policy {p.policy_id}: {e}"
                log.exception("dns update failed for policy %d", p.policy_id)
        for pid, prev in before.items():
            if prev.dns_stub_port is not None:
                with contextlib.suppress(Exception):
                    await self._dns.stop(pid)

    def _schedule_retry(self) -> None:
        if self._retry_task is not None and not self._retry_task.done():
            return
        delay = self._retry_delay
        self._retry_delay = min(self._retry_delay * 2, self._retry_max)

        async def retry() -> None:
            await asyncio.sleep(delay)
            self._retry_task = None
            await self.reconcile()

        self._retry_task = asyncio.get_running_loop().create_task(retry())

    async def disable(self) -> None:
        """Remove all rules and stop all stubs until ``enable``."""
        async with self._lock:
            self.enabled = False
            self._cancel_retry()
            if self._dns is not None and self.applied is not None:
                for p in self.applied.policies:
                    if p.dns_stub_port is not None:
                        with contextlib.suppress(Exception):
                            await self._dns.stop(p.policy_id)
            await self._backend.teardown()
            self.applied = None

    async def enable(self) -> None:
        self.enabled = True
        await self.reconcile()

    def _cancel_retry(self) -> None:
        if self._retry_task is not None:
            self._retry_task.cancel()
            self._retry_task = None

    async def close(self) -> None:
        self._cancel_retry()
