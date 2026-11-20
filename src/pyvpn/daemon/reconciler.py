"""Reconcile loop: keep the installed state equal to the planned state.

Every input change (config, target statuses, app bindings, destination sets)
recomputes the plan under one lock and applies it if it differs from what is
installed. Applies are serialized, so the plan applied last always reflects
the latest inputs.

DNS answers take a fast path (``add_dests``): the addresses are recorded and
pushed with ``Backend.add_to_set`` under the same lock, so a concurrent full
apply can never drop them. The callback only returns once the destination is
governed by the installed rules; in every other case (nothing installed yet,
disabled, mid-batch, config replaced while waiting, push failed) it raises, so
the stub answers SERVFAIL instead of releasing the reply.

DNS stubs are tracked separately from the routing plan (``dns_applied``): a
failed start or update is retried on the next reconcile even when the routing
plan is unchanged, and a stub whose update failed is stopped so it never keeps
answering with stale settings.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import replace

from pyvpn.config.models import Config
from pyvpn.daemon.planner import build_plan
from pyvpn.platform.base import Backend
from pyvpn.services import DnsService, RuleMatcher
from pyvpn.state import AppBinding, DestSet, PolicyPlan, RoutingPlan, TargetStatus

log = logging.getLogger(__name__)

_DNS_FIELDS = ("route", "interface", "gateway", "leak", "dns_stub_port")


def _carry_learned_dests(
    old: Config | None, new: Config, learned: Mapping[int, DestSet]
) -> dict[int, DestSet]:
    """Keep DNS-learned destinations for policies whose domain rules survive.

    Apps keep using cached answers after a reload, so dropping the learned
    addresses would send them out the default route (even under
    ``on_down: block``) until they query DNS again. A policy keeps its set
    when one with the same name and the same ``domains`` exists in the new
    config; ids are remapped because they follow config order.
    """
    if old is None or not learned:
        return {}
    old_ids = {p.name: (i, p.domains) for i, p in enumerate(old.policies, start=1)}
    out: dict[int, DestSet] = {}
    for new_id, policy in enumerate(new.policies, start=1):
        prev = old_ids.get(policy.name)
        if prev is None or prev[1] != policy.domains or not policy.domains:
            continue
        dests = learned.get(prev[0])
        if dests:
            out[new_id] = replace(dests, policy_id=new_id)
    return out


def _dns_changed(old: PolicyPlan | None, new: PolicyPlan) -> bool:
    return old is None or any(getattr(old, f) != getattr(new, f) for f in _DNS_FIELDS)


class DnsNotGoverned(RuntimeError):
    """The answered destination is not (yet) covered by installed rules."""


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
        self.matcher: RuleMatcher | None = None
        self.statuses: dict[str, TargetStatus] = {}
        self.bindings: dict[int, AppBinding] = {}
        self.static_dests: dict[int, DestSet] = {}
        self.dynamic_dests: dict[int, DestSet] = {}

        self.enabled = True
        self.applied: RoutingPlan | None = None
        self.dns_applied: dict[int, PolicyPlan] = {}
        self.last_error: str | None = None
        # ``_generation`` identifies the config held in ``self.config``: every
        # swap takes a fresh value and a rollback restores the old one, so a
        # value is never reused. ``_committed`` is the generation of the last
        # committed config; it only moves once a commit succeeds. Inputs that
        # arrive outside the lock (DNS answers, app bindings) capture
        # ``_committed`` and are dropped if ``_generation`` differs once they
        # hold the lock, i.e. if their policy ids may mean something else.
        self._generations = itertools.count(1)
        self._generation = 0
        self._committed = 0

    # --- inputs ---------------------------------------------------------------

    async def set_config(
        self,
        config: Config,
        static_sets: Iterable[DestSet] = (),
        *,
        matcher: RuleMatcher | None = None,
    ) -> None:
        """Install a new config; apply failures are retried in the background.

        Policy ids may shift, so per-id state is reset (DNS-learned
        destinations carry over for unchanged policies). Callers rebind apps
        inside ``batch()`` to avoid an unbound window, or use
        ``commit_config`` to apply config and bindings in one step."""
        async with self._lock:
            self._swap_config(config, static_sets, {})
            self.matcher = matcher
            self._committed = self._generation
        await self.reconcile()

    async def commit_config(
        self,
        config: Config,
        static_sets: Iterable[DestSet],
        bindings: Mapping[int, AppBinding],
        *,
        matcher: RuleMatcher | None = None,
    ) -> None:
        """Replace config and bindings and apply them as one step.

        Stop the old DNS listeners before changing routing. Activate the
        matcher and generation together before reopening the listeners.
        On failure before commit, restore the previous config and listeners.
        """
        async with self._lock:
            saved = self._snapshot()
            installed = self.applied
            plan = None
            try:
                if self.enabled:
                    await self._quiesce_dns_locked()
                self._swap_config(config, static_sets, bindings)
                if self.enabled:
                    plan = self.plan()
                    assert plan is not None
                    await self._apply_locked(plan)
            except (Exception, asyncio.CancelledError):
                self._restore(saved)
                if self.enabled and installed is not None:
                    await self._sync_dns_locked(installed)
                raise
            self.matcher = matcher
            self._committed = self._generation
            if plan is not None:
                await self._sync_dns_locked(plan)

    def _swap_config(
        self,
        config: Config,
        static_sets: Iterable[DestSet],
        bindings: Mapping[int, AppBinding],
    ) -> None:
        self.dynamic_dests = _carry_learned_dests(self.config, config, self.dynamic_dests)
        self.config = config
        self.bindings = dict(bindings)
        self.static_dests = {}
        for s in static_sets:
            prev = self.static_dests.get(s.policy_id)
            self.static_dests[s.policy_id] = s if prev is None else prev | s
        self._generation = next(self._generations)

    def _snapshot(self) -> tuple[object, ...]:
        return (
            self.config,
            self.bindings,
            self.static_dests,
            self.dynamic_dests,
            self._generation,
        )

    def _restore(self, saved: tuple[object, ...]) -> None:
        (
            self.config,
            self.bindings,
            self.static_dests,
            self.dynamic_dests,
            self._generation,
        ) = saved  # type: ignore[assignment]

    async def update_targets(self, statuses: Mapping[str, TargetStatus]) -> None:
        self.statuses = dict(statuses)
        await self.reconcile()

    async def update_binding(self, binding: AppBinding) -> None:
        """Record an app manager binding for the config committed when it arrived.

        Runs under the lock, so it cannot interleave with ``commit_config``
        (whose ``_restore`` would otherwise drop it). A binding that was
        waiting while the config changed is dropped: its policy id may now
        name a different policy, and the commit installed fresh bindings for
        the new config. A binding that arrives while a commit is in flight belongs
        to the old config: it survives if the commit is rolled back.
        """
        generation = self._committed
        async with self._lock:
            if generation != self._generation:
                log.info("dropping binding for policy %d: config changed", binding.policy_id)
                return
            if self.config is None or not 1 <= binding.policy_id <= len(self.config.policies):
                log.warning("ignoring binding for unknown policy %d", binding.policy_id)
                return
            self.bindings[binding.policy_id] = binding
            if not self._batch_depth:
                await self._reconcile_locked()

    async def add_dests(self, dests: DestSet) -> None:
        """DNS callback: return only once ``dests`` is governed by installed rules."""
        generation = self._committed
        async with self._lock:
            if generation != self._generation:
                raise DnsNotGoverned("config changed while the answer was pending")
            if not self.enabled or self.applied is None or self._batch_depth:
                raise DnsNotGoverned("no rules installed for this policy yet")
            plans = list(self.applied.policies)
            for i, p in enumerate(plans):
                if p.policy_id != dests.policy_id:
                    continue
                if p.dests is None:
                    return  # the policy already routes every destination
                await self._backend.add_to_set(dests)
                prev = self.dynamic_dests.get(dests.policy_id)
                self.dynamic_dests[dests.policy_id] = dests if prev is None else prev | dests
                plans[i] = replace(p, dests=p.dests | dests)
                self.applied = RoutingPlan(tuple(plans))
                return
            raise DnsNotGoverned(f"policy {dests.policy_id} is not installed")

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
        if plan is None:
            return
        if plan != self.applied:
            try:
                await self._apply_locked(plan)
            except Exception as e:  # backend keeps the previous state on failure
                self.last_error = f"apply failed: {e}"
                log.exception("apply failed; retrying")
                self._schedule_retry()
                return
        await self._sync_dns_locked(plan)

    async def _apply_locked(self, plan: RoutingPlan) -> None:
        await self._backend.apply(plan)
        self.applied = plan
        self.last_error = None

    async def _quiesce_dns_locked(self) -> None:
        if self._dns is None:
            return
        ids = set(self.dns_applied)
        if self.applied is not None:
            # Include configured ports even if an earlier listener update failed.
            ids.update(p.policy_id for p in self.applied.policies if p.dns_stub_port is not None)
        for pid in sorted(ids):
            # A failed stop may already have closed the listener. Resync it on rollback.
            self.dns_applied.pop(pid, None)
            await self._dns.stop(pid)

    async def _sync_dns_locked(self, plan: RoutingPlan) -> None:
        """Make the running stubs match ``plan``; retry anything that failed."""
        ok = True
        if self._dns is not None:
            want = {p.policy_id: p for p in plan.policies if p.dns_stub_port is not None}
            for pid in [pid for pid in self.dns_applied if pid not in want]:
                try:
                    await self._dns.stop(pid)
                    del self.dns_applied[pid]
                except Exception as e:
                    ok = False
                    self.last_error = f"dns policy {pid}: stop failed: {e}"
                    log.exception("dns stop failed for policy %d", pid)
            for pid, p in want.items():
                if not _dns_changed(self.dns_applied.get(pid), p):
                    continue
                try:
                    await self._dns.start(p)
                    self.dns_applied[pid] = p
                except Exception as e:
                    ok = False
                    self.last_error = f"dns policy {pid}: {e}"
                    log.exception("dns update failed for policy %d", pid)
                    # Fail closed: never leave a stub running with stale settings.
                    self.dns_applied.pop(pid, None)
                    with contextlib.suppress(Exception):
                        await self._dns.stop(pid)
        if ok:
            self._retry_delay = self._retry_initial
        else:
            self._schedule_retry()

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
            if self._dns is not None:
                for pid in list(self.dns_applied):
                    with contextlib.suppress(Exception):
                        await self._dns.stop(pid)
            self.dns_applied = {}
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
