"""The daemon: wires config, targets, apps, DNS, rules and the backend.

Every collaborator is injected through the protocols in ``pyvpn.services`` and
``pyvpn.platform.base``, so the daemon runs unchanged against fakes (tests) or
the real Linux parts (Phase 2).
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import os
from collections.abc import Awaitable, Callable
from typing import Any

from pyvpn.config.models import Config
from pyvpn.constants import SOCKET_PATH
from pyvpn.daemon.api import AppsEntry, PlacePidParams, PolicyStatus, StatusResult
from pyvpn.daemon.persistence import PersistentState, StateStore
from pyvpn.daemon.reconciler import Reconciler
from pyvpn.daemon.server import ApiError, ApiServer, PeerCred
from pyvpn.platform.base import Backend
from pyvpn.services import AppManager, DnsService, RuleMatcherFactory, TargetWatcher
from pyvpn.state import AppBinding

log = logging.getLogger(__name__)

ConfigLoader = Callable[[], Config]
AuditFn = Callable[[], Awaitable[Any]]


class Daemon:
    def __init__(
        self,
        *,
        config_loader: ConfigLoader,
        backend: Backend,
        targets: TargetWatcher,
        apps: AppManager,
        dns: DnsService | None = None,
        matcher_factory: RuleMatcherFactory | None = None,
        audit: AuditFn | None = None,
        store: StateStore | None = None,
        socket_path: str | os.PathLike[str] = SOCKET_PATH,
        teardown_on_stop: bool = True,
    ) -> None:
        self._load = config_loader
        self._backend = backend
        self._targets = targets
        self._apps = apps
        self._dns = dns
        self._matcher_factory = matcher_factory
        self._audit = audit
        self._store = store
        self._teardown_on_stop = teardown_on_stop
        self.reconciler = Reconciler(backend, dns)
        self.server = ApiServer(socket_path, self.handle)
        self._tasks: list[asyncio.Task[None]] = []
        self._stopped = asyncio.Event()
        # Serializes reloads with pid placement, so a placement always resolves
        # policy ids against the committed config.
        self._config_lock = asyncio.Lock()

    @property
    def config(self) -> Config:
        assert self.reconciler.config is not None
        return self.reconciler.config

    # --- lifecycle --------------------------------------------------------------

    async def start(self) -> None:
        config = self._load()
        if self._store is not None and not self._store.load().enabled:
            self.reconciler.enabled = False
        if self._dns is not None:
            self._dns.on_answer(self.reconciler.add_dests)
        await self._install(config, rollback=False)
        if self.reconciler.enabled and self.reconciler.applied is None:
            log.error(
                "initial apply failed (%s); pid placement stays unavailable until it succeeds",
                self.reconciler.last_error,
            )
        self._spawn(self._watch_targets(), "targets")
        self._spawn(self._watch_bindings(), "bindings")
        await self.server.start()
        log.info("pyvpn daemon started with %d policies", len(config.policies))

    async def stop(self) -> None:
        await self.server.close()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        self._tasks.clear()
        await self.reconciler.close()
        if self._teardown_on_stop and self.reconciler.enabled:
            await self.reconciler.disable()
        self._stopped.set()

    async def wait_stopped(self) -> None:
        await self._stopped.wait()

    async def _install(self, config: Config, *, rollback: bool) -> None:
        """Stage a config's bindings, then commit config + bindings in one apply.

        The previous config stays in force (and keeps resolving policy ids)
        until the commit. With ``rollback``, a failed bind or apply restores the
        previous bindings and raises; without it (startup), a failed apply is
        retried by the reconciler.
        """
        static = self._matcher_factory(config).static_sets() if self._matcher_factory else []
        old = self.reconciler.config
        staged: dict[int, AppBinding] = {}
        try:
            for pid, policy in enumerate(config.policies, start=1):
                staged[pid] = await self._apps.bind(pid, policy, config.app_groups)
            if rollback:
                await self.reconciler.commit_config(config, static, staged)
            else:
                async with self.reconciler.batch():  # one apply; failures are retried
                    await self.reconciler.set_config(config, static)
                    for binding in staged.values():
                        await self.reconciler.update_binding(binding)
        except Exception:
            if old is not None:
                # Include the id whose bind failed: it may be half-changed.
                await self._rebind(old, min(len(staged) + 1, len(config.policies)))
            raise
        if old is not None:
            for pid in range(len(config.policies) + 1, len(old.policies) + 1):
                with contextlib.suppress(Exception):
                    await self._apps.unbind(pid)

    async def _rebind(self, old: Config, touched: int) -> None:
        """Restore the app manager's bindings for the still-active ``old`` config."""
        for pid in range(1, touched + 1):
            try:
                if pid <= len(old.policies):
                    await self._apps.bind(pid, old.policies[pid - 1], old.app_groups)
                else:
                    await self._apps.unbind(pid)
            except Exception:
                log.exception("rollback of policy %d binding failed", pid)

    def _spawn(self, coro: Awaitable[None], name: str) -> None:
        self._tasks.append(asyncio.ensure_future(coro))
        self._tasks[-1].set_name(f"pyvpn-{name}")

    async def _watch_targets(self) -> None:
        reason = "target watcher ended"
        try:
            async for statuses in self._targets.statuses():
                await self.reconciler.update_targets(statuses)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.exception("target watcher failed")
            reason = f"target watcher failed: {e}"
        # The watcher is gone: we can no longer tell whether a target is up.
        # Treat every target as down so kill-switch policies block.
        log.error("%s; marking all targets down", reason)
        await self.reconciler.update_targets({})
        self.reconciler.last_error = reason

    async def _watch_bindings(self) -> None:
        try:
            async for binding in self._apps.bindings():
                await self.reconciler.update_binding(binding)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.exception("app manager stream failed")
            self.reconciler.last_error = f"app manager failed: {e}"

    # --- API --------------------------------------------------------------------

    async def handle(self, method: str, params: dict[str, Any], peer: PeerCred | None) -> Any:
        if method == "status":
            return dataclasses.asdict(self.status())
        if method == "apps":
            return [dataclasses.asdict(e) for e in self.apps()]
        if method == "place_pid":
            return await self._place_pid(params, peer)
        if method == "reload":
            self._require_admin(peer)
            await self.reload()
            return None
        if method == "disable":
            self._require_admin(peer)
            await self.disable()
            return None
        if method == "audit":
            if self._audit is None:
                raise ApiError("unavailable", "audit is not available")
            return await self._audit()
        raise ApiError("unknown_method", method)

    @staticmethod
    def _require_admin(peer: PeerCred | None) -> None:
        if peer is None:
            raise ApiError("forbidden", "caller credentials unavailable")
        if peer.uid not in (0, os.geteuid()):
            raise ApiError("forbidden", "only root may do this")

    def status(self) -> StatusResult:
        r = self.reconciler
        applied = {p.policy_id: p for p in r.applied.policies} if r.applied else {}
        planned = r.plan()
        planned_by_id = {p.policy_id: p for p in planned.policies} if planned else {}
        policies = []
        for pid, pol in enumerate(self.config.policies, start=1):
            p = applied.get(pid) or planned_by_id.get(pid)
            policies.append(
                PolicyStatus(
                    id=pid,
                    name=pol.name,
                    route=p.route if p else "unknown",
                    target=p.target if p else None,
                    interface=p.interface if p else None,
                    on_down=pol.on_down,
                )
            )
        targets = {
            name: {"interface": s.interface, "usable": s.usable} for name, s in r.statuses.items()
        }
        return StatusResult(r.enabled, policies, targets, r.last_error)

    def apps(self) -> list[AppsEntry]:
        out = []
        for pid, pol in enumerate(self.config.policies, start=1):
            b = self.reconciler.bindings.get(pid)
            out.append(
                AppsEntry(
                    policy_id=pid,
                    policy=pol.name,
                    cgroup_paths=list(b.cgroup_paths) if b else [],
                    uids=list(b.uids) if b else [],
                    any_process=b.any_process if b else not pol.apps,
                )
            )
        return out

    async def _place_pid(self, params: dict[str, Any], peer: PeerCred | None) -> dict[str, int]:
        try:
            p = PlacePidParams(**params)
        except TypeError as e:
            raise ApiError("bad_request", str(e)) from None
        if not isinstance(p.pid, int) or isinstance(p.pid, bool) or p.pid <= 0:
            raise ApiError("bad_request", "pid must be a positive integer")
        if peer is None:
            raise ApiError("forbidden", "caller credentials unavailable")
        if peer.uid != 0 and peer.pid != p.pid:
            raise ApiError("forbidden", "unprivileged callers may only place their own pid")
        async with self._config_lock:
            r = self.reconciler
            if r.enabled and r.applied is None:
                raise ApiError("unavailable", "routing rules are not installed yet")
            pid = self._resolve_policy(p.policy)
            await self._apps.place_pid(p.pid, pid)
        return {"policy_id": pid}

    def _resolve_policy(self, ref: str | int) -> int:
        n = len(self.config.policies)
        if isinstance(ref, int) and not isinstance(ref, bool):
            if 1 <= ref <= n:
                return ref
        elif isinstance(ref, str):
            with contextlib.suppress(KeyError):
                return self.config.policy_id(ref)
        raise ApiError("not_found", f"no policy {ref!r}")

    async def reload(self) -> None:
        try:
            config = self._load()
        except Exception as e:
            raise ApiError("bad_request", f"config: {e}") from None
        async with self._config_lock:
            try:
                await self._install(config, rollback=True)
            except Exception as e:
                log.exception("reload failed; previous config kept")
                raise ApiError("internal", f"reload failed, previous config kept: {e}") from None
        if not self.reconciler.enabled:
            await self.reconciler.enable()
            self._persist()

    async def disable(self) -> None:
        await self.reconciler.disable()
        self._persist()

    def _persist(self) -> None:
        if self._store is not None:
            self._store.save(PersistentState(enabled=self.reconciler.enabled))
