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
from pyvpn.constants import SOCKET_PATH, policy_cgroup
from pyvpn.daemon.api import AppsEntry, PlacePidParams, PolicyStatus, StatusResult
from pyvpn.daemon.persistence import PersistentState, StateStore
from pyvpn.daemon.reconciler import Reconciler
from pyvpn.daemon.server import ApiError, ApiServer, PeerCred, acquire_instance_lock
from pyvpn.platform.base import Backend
from pyvpn.services import (
    AppManager,
    DnsService,
    RuleMatcher,
    RuleMatcherFactory,
    TargetWatcher,
)
from pyvpn.state import AppBinding

log = logging.getLogger(__name__)

ConfigLoader = Callable[[], Config]
NOT_INSTALLED = "not_installed"  # PolicyStatus.route when no rules are installed
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
        # Required: the enabled flag and cgroup reservations must survive a
        # restart. Pass ``None`` only to opt out explicitly (tests).
        store: StateStore | None,
        socket_path: str | os.PathLike[str] = SOCKET_PATH,
        teardown_on_stop: bool = False,
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
        self.reconciler.on_learned = self._save_learned
        self.server = ApiServer(socket_path, self.handle)
        self._tasks: list[asyncio.Task[None]] = []
        self._stopped = asyncio.Event()
        self._lifecycle_lock = asyncio.Lock()
        self._instance_fd: int | None = None
        # Keep policy resolution, routing changes and state writes serialized.
        self._config_lock = asyncio.Lock()
        # Cgroups may still contain processes after their selectors change.
        self._cgroup_policy_names: dict[int, str] = {}
        # Failures of the target/app watchers: they do not recover, so they
        # stay in ``status`` (an apply succeeding later does not clear them).
        self._watcher_errors: dict[str, str] = {}

    @property
    def config(self) -> Config:
        assert self.reconciler.config is not None
        return self.reconciler.config

    def active_matcher(self) -> RuleMatcher:
        """The rule matcher of the committed config, for the DNS stubs.

        The composition root hands this to the DNS service, e.g.
        ``PolicyDnsService(matcher_factory=lambda: daemon.active_matcher())``
        (late-bound, since the daemon takes the service). The reconciler
        activates it before starting DNS listeners for the new config.
        Raises while no matcher is available so the stub answers SERVFAIL.
        """
        matcher = self.reconciler.matcher
        if matcher is None:
            raise RuntimeError("no rule matcher for the active config")
        return matcher

    # --- lifecycle --------------------------------------------------------------

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self._instance_fd is not None:
                raise RuntimeError("daemon is already started")
            self._instance_fd = acquire_instance_lock(self.server.path)
            self._stopped.clear()
            try:
                await self.server.start(start_serving=False)
                config = self._load()
                if self._store is not None:
                    state = self._store.load()
                    self.reconciler.enabled = state.enabled
                    # Apps placed by a previous daemon are still in their cgroups.
                    self._cgroup_policy_names.update(state.policy_slots)
                    # Addresses apps may still have cached: govern them from
                    # the first apply on instead of emptying their sets.
                    self.reconciler.restore_learned(state.learned)
                self._validate_policy_slots(config)
                if self._dns is not None:
                    self._dns.on_answer(self.reconciler.add_dests)
                await self._install(config, reload=False)
                if self.reconciler.enabled and self.reconciler.applied is None:
                    log.error(
                        "initial apply failed (%s); placement unavailable until it succeeds",
                        self.reconciler.last_error,
                    )
                self._spawn(self._watch_targets(), "targets")
                self._spawn(self._watch_bindings(), "bindings")
                await self.server.serve()
            except BaseException:
                await self._stop(teardown=False)
                raise
            log.info("pyvpn daemon started with %d policies", len(config.policies))

    async def stop(self) -> None:
        """Stop serving. Installed rules stay in force (kill switches keep
        blocking across a restart; the next daemon's apply replaces them
        atomically). Only ``disable`` or ``teardown_on_stop`` (uninstall)
        removes them."""
        async with self._lifecycle_lock:
            await self._stop(teardown=self._teardown_on_stop)

    async def _stop(self, *, teardown: bool) -> None:
        try:
            if self._instance_fd is None:
                return
            try:
                await self.server.close()
            finally:
                for t in self._tasks:
                    t.cancel()
                for t in self._tasks:
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await t
                self._tasks.clear()
                await self.reconciler.close()
            if teardown and self.reconciler.enabled:
                await self.reconciler.disable()
        finally:
            if self._instance_fd is not None:
                os.close(self._instance_fd)
                self._instance_fd = None
            self._stopped.set()  # wait_stopped() must not hang on a failed teardown

    async def wait_stopped(self) -> None:
        await self._stopped.wait()

    async def _install(self, config: Config, *, reload: bool) -> None:
        """Stage a config's bindings, then commit config + bindings in one apply.

        The previous config stays in force (and keeps resolving policy ids)
        until the commit. On reload, a failed bind, state write or apply
        restores the previous bindings and raises. Startup apply failures
        are retried by the reconciler.
        """
        self._check_supported(config)
        matcher = self._matcher_factory(config) if self._matcher_factory else None
        static = matcher.static_sets() if matcher is not None else []
        old = self.reconciler.config
        old_slots = self._cgroup_policy_names
        enabled = self.reconciler.enabled  # reload never changes it (see ``enable``)
        saved = False
        staged: dict[int, AppBinding] = {}
        try:
            for pid, policy in enumerate(config.policies, start=1):
                staged[pid] = await self._apps.bind(pid, policy, config.app_groups)
            slots = old_slots | {
                pid: policy.name
                for pid, policy in enumerate(config.policies, start=1)
                if policy.apps or staged[pid].cgroup_paths
            }
            if slots != old_slots:
                self._save_state(enabled=enabled, slots=slots)
                saved = True
            if reload:
                await self.reconciler.commit_config(config, static, staged, matcher=matcher)
            else:
                async with self.reconciler.batch():  # one apply; failures are retried
                    await self.reconciler.set_config(config, static, matcher=matcher)
                    for binding in staged.values():
                        await self.reconciler.update_binding(binding)
        except (Exception, asyncio.CancelledError):
            if self.reconciler.config is config:
                # Past the commit point (e.g. cancelled while the new DNS
                # listeners start): the new rules are installed, so keep the
                # new bindings and saved reservations that go with them.
                log.warning("new config committed; interrupted while starting its DNS listeners")
                raise
            if saved:
                try:
                    self._save_state(enabled=enabled, slots=old_slots)
                except OSError:
                    # Keep the saved reservations if restoring the file fails.
                    log.exception("could not restore previous daemon state")
            if old is not None:
                # Include the id whose bind failed: it may be half-changed.
                await self._rebind(old, min(len(staged) + 1, len(config.policies)))
            raise
        if old is not None:
            for pid in range(len(config.policies) + 1, len(old.policies) + 1):
                with contextlib.suppress(Exception):
                    await self._apps.unbind(pid)

    def _check_supported(self, config: Config) -> None:
        """Refuse configs this daemon cannot enforce, before anything changes.

        - destination rules without a rule matcher would install empty sets;
        - DNS stubs without a DNS service would redirect DNS to nothing;
        - hostname rules need a stub to learn addresses, which only runs with
          ``dns_via_target`` (otherwise their traffic is never matched);
        - the target watcher is fixed at startup, so reload cannot change the
          target definitions.
        """
        for policy in config.policies:
            where = f"policy {policy.name!r}"
            if policy.domains and self._matcher_factory is None:
                raise ApiError("bad_request", f"{where}: destination rules need a rule matcher")
            if policy.leak.dns_via_target and self._dns is None:
                raise ApiError("bad_request", f"{where}: dns_via_target needs a DNS service")
            hostnames = [d for d in policy.domains if not _is_address_rule(d)]
            if hostnames and not policy.leak.dns_via_target:
                raise ApiError(
                    "bad_request",
                    f"{where}: hostname rules ({hostnames[0]!r}) need dns_via_target: true, "
                    "since only the policy's DNS stub can learn their addresses",
                )
        old = self.reconciler.config
        if old is not None and old.targets != config.targets:
            raise ApiError(
                "bad_request", "reload cannot change targets yet; restart the daemon instead"
            )

    def _validate_policy_slots(self, config: Config) -> None:
        names = tuple(policy.name for policy in config.policies)
        if len(set(names)) != len(names):
            raise ApiError("bad_request", "policy names must be unique")
        for policy_id, name in self._cgroup_policy_names.items():
            if policy_id > len(names) or names[policy_id - 1] != name:
                raise ApiError(
                    "bad_request",
                    f"reload must keep policy {name!r} at position {policy_id} "
                    "because its cgroup may still contain running apps",
                )

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
        self._watcher_errors["targets"] = reason
        await self.reconciler.update_targets({})

    async def _watch_bindings(self) -> None:
        try:
            async for binding in self._apps.bindings():
                await self.reconciler.update_binding(binding)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.exception("app manager stream failed")
            self._watcher_errors["apps"] = f"app manager failed: {e}"

    # --- API --------------------------------------------------------------------

    async def handle(self, method: str, params: dict[str, Any], peer: PeerCred | None) -> Any:
        if method == "status":
            async with self._config_lock:  # never show a staged, uncommitted config
                return dataclasses.asdict(self.status())
        if method == "apps":
            async with self._config_lock:
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
        if method == "enable":
            self._require_admin(peer)
            await self.enable()
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
        """Report what is installed, not what is planned.

        Until an apply succeeds (or while disabled) no rules exist, so every
        policy reports ``not_installed`` rather than the route it would get.
        """
        r = self.reconciler
        applied = {p.policy_id: p for p in r.applied.policies} if r.applied else {}
        policies = []
        for pid, pol in enumerate(self.config.policies, start=1):
            p = applied.get(pid)
            policies.append(
                PolicyStatus(
                    id=pid,
                    name=pol.name,
                    route=p.route if p else NOT_INSTALLED,
                    target=p.target if p else None,
                    interface=p.interface if p else None,
                    on_down=pol.on_down,
                )
            )
        targets = {
            name: {"interface": s.interface, "usable": s.usable} for name, s in r.statuses.items()
        }
        errors = [*self._watcher_errors.values(), r.last_error]
        return StatusResult(r.enabled, policies, targets, "; ".join(e for e in errors if e) or None)

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
        if peer.uid != 0:
            if peer.pid != p.pid:
                raise ApiError("forbidden", "unprivileged callers may only place their own pid")
            # SO_PEERCRED's pid is from connect time; the pidfd proves the
            # process is still that one, not a later process with a reused PID.
            if not peer.same_process_alive():
                raise ApiError("forbidden", "cannot verify that the calling process still exists")
        async with self._config_lock:
            if peer.uid != 0 and not peer.same_process_alive():
                # The caller may have exited while waiting for the lock.
                raise ApiError("forbidden", "cannot verify that the calling process still exists")
            r = self.reconciler
            if not r.enabled:
                raise ApiError("unavailable", "routing is disabled")
            if r.applied is None:
                raise ApiError("unavailable", "routing rules are not installed yet")
            pid = self._resolve_policy(p.policy)
            installed = next((x for x in r.applied.policies if x.policy_id == pid), None)
            governed = installed is not None and (
                installed.apps.any_process or policy_cgroup(pid) in installed.apps.cgroup_paths
            )
            if not governed:
                raise ApiError(
                    "unavailable", f"policy {pid}'s placement cgroup is not governed by its rules"
                )
            if pid not in self._cgroup_policy_names:
                name = self.config.policies[pid - 1].name
                self._save_state(enabled=True, slots=self._cgroup_policy_names | {pid: name})
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
        """Swap in the config file's current contents.

        Reload never changes the enabled state: after ``disable`` the new
        config is bound but nothing is installed until ``enable``.
        """
        try:
            config = self._load()
        except Exception as e:
            raise ApiError("bad_request", f"config: {e}") from None
        async with self._config_lock:
            self._validate_policy_slots(config)
            try:
                await self._install(config, reload=True)
            except Exception as e:
                log.exception("reload failed; previous config kept")
                raise ApiError("internal", f"reload failed, previous config kept: {e}") from None

    async def disable(self) -> None:
        async with self._config_lock:
            await self.reconciler.disable()
            self._save_state(enabled=False, slots=self._cgroup_policy_names)

    async def enable(self) -> None:
        """Undo ``disable``. A failed apply is retried in the background
        (``status`` shows ``not_installed`` and ``last_error`` meanwhile)."""
        async with self._config_lock:
            if self.reconciler.enabled:
                return
            self._save_state(enabled=True, slots=self._cgroup_policy_names)
            await self.reconciler.enable()

    def _save_state(self, *, enabled: bool, slots: dict[int, str]) -> None:
        if self._store is not None:
            self._store.save(
                PersistentState(
                    enabled=enabled,
                    policy_slots=tuple(sorted(slots.items())),
                    learned=self.reconciler.learned_entries(),
                )
            )
        self._cgroup_policy_names = slots

    def _save_learned(self) -> None:
        if self._store is not None and self.reconciler.config is not None:
            self._save_state(enabled=self.reconciler.enabled, slots=self._cgroup_policy_names)


def _is_address_rule(rule: str) -> bool:
    """``asn:``/``cidr:``/``ip:`` rules need no DNS to be enforced."""
    head = rule.strip().lower()
    return head.startswith(("asn:", "cidr:", "ip:"))
