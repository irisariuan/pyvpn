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
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from dataclasses import replace
from ipaddress import IPv4Network, IPv6Network, ip_network

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
    when one with the same name exists in the new config and its new
    ``domains`` only add rules (no exclusions) to the old ones, so every
    learned address still matches; ids are remapped because they follow
    config order. Any other edit starts the set empty (fail closed).
    """
    if old is None or not learned:
        return {}
    old_ids = {p.name: (i, p.domains) for i, p in enumerate(old.policies, start=1)}
    out: dict[int, DestSet] = {}
    for new_id, policy in enumerate(new.policies, start=1):
        prev = old_ids.get(policy.name)
        if prev is None or not policy.domains or not _only_adds_rules(prev[1], policy.domains):
            continue
        dests = learned.get(prev[0])
        if dests:
            out[new_id] = replace(dests, policy_id=new_id)
    return out


def _carry_restored(
    restored: Mapping[str, tuple[tuple[str, ...], DestSet]], new: Config
) -> dict[int, DestSet]:
    """``_carry_learned_dests`` for sets saved by a previous daemon."""
    out: dict[int, DestSet] = {}
    for new_id, policy in enumerate(new.policies, start=1):
        prev = restored.get(policy.name)
        if prev is None or not policy.domains or not _only_adds_rules(prev[0], policy.domains):
            continue
        if prev[1]:
            out[new_id] = replace(prev[1], policy_id=new_id)
    return out


def _only_adds_rules(old: tuple[str, ...], new: tuple[str, ...]) -> bool:
    """Whether ``new`` keeps every rule of ``old`` and adds only plain rules."""
    kept = set(new)
    if not set(old) <= kept:
        return False
    return not any(rule.lstrip().startswith("!") for rule in kept - set(old))


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
        # Stubs whose stop failed: they may still be listening, so keep
        # retrying the stop until it succeeds.
        self._dns_stop_pending: set[int] = set()
        # Called (under the lock) whenever DNS-learned destinations change,
        # so the daemon can persist them for its successor.
        self.on_learned: Callable[[], None] | None = None
        # Learned sets saved by a previous daemon, by policy name; used once,
        # by the first config swap, before the first apply.
        self._restored: dict[str, tuple[tuple[str, ...], DestSet]] = {}
        # Learned destinations the last save did not persist; any DNS answer
        # retries the save before it is acknowledged.
        self._learned_unsaved = False
        self._apply_error: str | None = None
        self._dns_error: str | None = None
        self._retry_wanted = False
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

    @property
    def last_error(self) -> str | None:
        """The current apply or DNS failure, cleared once that part recovers."""
        errors = [e for e in (self._apply_error, self._dns_error) if e]
        return "; ".join(errors) or None

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
            with contextlib.suppress(Exception):  # retried on the next DNS answer
                self._notify_learned()
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
            with contextlib.suppress(Exception):  # retried on the next DNS answer
                self._notify_learned()
            if plan is not None:
                await self._sync_dns_locked(plan)

    def restore_learned(
        self, entries: Iterable[tuple[str, tuple[str, ...], tuple[str, ...]]]
    ) -> None:
        """Seed destinations a previous daemon learned (``learned_entries``).

        Must run before the first config: that swap carries them over (same
        rules as a reload), so the first apply does not empty sets that
        surviving apps still rely on.
        """
        restored: dict[str, tuple[tuple[str, ...], DestSet]] = {}
        for name, domains, nets in entries:
            v4: set[IPv4Network] = set()
            v6: set[IPv6Network] = set()
            for n in nets:
                net = ip_network(n, strict=False)
                if isinstance(net, IPv4Network):
                    v4.add(net)
                else:
                    v6.add(net)
            restored[name] = (domains, DestSet(0, frozenset(v4), frozenset(v6)))
        self._restored = restored

    def learned_entries(self) -> tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...]:
        """The committed config's learned destinations, by policy name."""
        if self.config is None:
            return ()
        out = []
        for pid, policy in enumerate(self.config.policies, start=1):
            d = self.dynamic_dests.get(pid)
            if d:
                nets = tuple(sorted(str(n) for n in (*d.v4, *d.v6)))
                out.append((policy.name, policy.domains, nets))
        return tuple(out)

    def _notify_learned(self) -> None:
        """Persist learned destinations; a failure is remembered for retry."""
        if self.on_learned is None:
            return
        try:
            self.on_learned()
        except Exception:
            self._learned_unsaved = True
            log.exception("could not save learned destinations")
            raise
        self._learned_unsaved = False

    def _swap_config(
        self,
        config: Config,
        static_sets: Iterable[DestSet],
        bindings: Mapping[int, AppBinding],
    ) -> None:
        if self.config is None and self._restored:
            self.dynamic_dests = _carry_restored(self._restored, config)
        else:
            self.dynamic_dests = _carry_learned_dests(self.config, config, self.dynamic_dests)
        self._restored = {}
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
                if self.dynamic_dests[dests.policy_id] != prev or self._learned_unsaved:
                    # Only acknowledge the answer once a successor daemon will
                    # also govern it: a failed save means SERVFAIL, and the
                    # next answer (even for the same address) retries it.
                    try:
                        self._notify_learned()
                    except Exception as e:
                        raise DnsNotGoverned(f"could not save learned destination: {e}") from e
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
            # Stop stubs whose settings change (e.g. main -> unreachable)
            # before routing changes, so none forwards with the old route.
            await self._stop_changed_dns_locked(plan)
            try:
                await self._apply_locked(plan)
            except Exception as e:  # backend keeps the previous state on failure
                self._apply_error = f"apply failed: {e}"
                log.exception("apply failed; retrying")
                self._schedule_retry()
                return
        await self._sync_dns_locked(plan)

    async def _apply_locked(self, plan: RoutingPlan) -> None:
        await self._backend.apply(plan)
        self.applied = plan
        self._apply_error = None

    async def _stop_dns_locked(self, pid: int) -> bool:
        """Stop one stub. A failed stop is remembered and retried, since the
        listener may still be live; it is never just forgotten."""
        assert self._dns is not None
        self.dns_applied.pop(pid, None)
        try:
            await self._dns.stop(pid)
        except Exception as e:
            self._dns_stop_pending.add(pid)
            self._dns_error = f"dns policy {pid}: stop failed: {e}"
            log.exception("dns stop failed for policy %d", pid)
            return False
        self._dns_stop_pending.discard(pid)
        return True

    async def _stop_all_dns_locked(self) -> bool:
        if self._dns is None:
            return True
        ids = set(self.dns_applied) | self._dns_stop_pending
        if self.applied is not None:
            # Include configured ports even if an earlier listener update failed.
            ids.update(p.policy_id for p in self.applied.policies if p.dns_stub_port is not None)
        ok = True
        for pid in sorted(ids):
            ok = await self._stop_dns_locked(pid) and ok
        return ok

    async def _quiesce_dns_locked(self) -> None:
        if not await self._stop_all_dns_locked():
            raise RuntimeError(self._dns_error or "dns stop failed")

    async def _stop_changed_dns_locked(self, plan: RoutingPlan) -> None:
        if self._dns is None:
            return
        want = {p.policy_id: p for p in plan.policies}
        for pid, old in list(self.dns_applied.items()):
            new = want.get(pid)
            if new is None or new.dns_stub_port is None or _dns_changed(old, new):
                await self._stop_dns_locked(pid)

    async def _sync_dns_locked(self, plan: RoutingPlan) -> None:
        """Make the running stubs match ``plan``; retry anything that failed."""
        ok = True
        if self._dns is not None:
            want = {p.policy_id: p for p in plan.policies if p.dns_stub_port is not None}
            stale = {pid for pid in self.dns_applied if pid not in want}
            # Retry pending stops first, also for stubs that should run: the
            # old listener may still hold the port.
            for pid in sorted(stale | self._dns_stop_pending):
                ok = await self._stop_dns_locked(pid) and ok
            for pid, p in want.items():
                if pid in self._dns_stop_pending:
                    continue  # still not stopped; retried later
                if not _dns_changed(self.dns_applied.get(pid), p):
                    continue
                try:
                    await self._dns.start(p)
                    self.dns_applied[pid] = p
                except Exception as e:
                    ok = False
                    self._dns_error = f"dns policy {pid}: {e}"
                    log.exception("dns update failed for policy %d", pid)
                    # Fail closed: never leave a stub running with stale settings.
                    await self._stop_dns_locked(pid)
        if ok:
            self._dns_error = None
            self._retry_delay = self._retry_initial
        else:
            self._schedule_retry()

    def _schedule_retry(self) -> None:
        """Retry soon. The task stays tracked until it finishes (including
        the reconcile it runs), so ``close()`` can wait for in-flight work."""
        self._retry_wanted = True
        if self._retry_task is not None and not self._retry_task.done():
            return

        async def retry() -> None:
            while self._retry_wanted:
                self._retry_wanted = False
                delay = self._retry_delay
                self._retry_delay = min(self._retry_delay * 2, self._retry_max)
                await asyncio.sleep(delay)
                await self.reconcile()

        self._retry_task = asyncio.get_running_loop().create_task(retry())

    async def disable(self) -> None:
        """Remove all rules and stop all stubs until ``enable``.

        Routing counts as disabled only once teardown succeeded. If it fails
        part-way, ``applied`` no longer describes the backend, so it is
        cleared and the active config is re-applied (enforcement resumes).
        """
        async with self._lock:
            self._cancel_retry()
            await self._stop_all_dns_locked()
            try:
                await self._backend.teardown()
            except Exception as e:
                self.applied = None
                self._apply_error = f"teardown failed: {e}"
                self._schedule_retry()
                raise
            self.enabled = False
            self.applied = None

    async def enable(self) -> None:
        self.enabled = True
        await self.reconcile()

    def _cancel_retry(self) -> None:
        self._retry_wanted = False
        if self._retry_task is not None:
            self._retry_task.cancel()
            self._retry_task = None

    async def close(self) -> None:
        """Stop background work and the DNS stubs; installed rules stay.

        Waits for an in-flight retry so nothing changes routing after the
        daemon gives up ownership, and stops the stubs so their callbacks
        cannot touch the backend afterwards.
        """
        task = self._retry_task
        self._cancel_retry()
        if task is not None:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        async with self._lock:
            await self._stop_all_dns_locked()
