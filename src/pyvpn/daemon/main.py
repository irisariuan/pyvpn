"""Composition root and ``pyvpn-daemon`` entry point (WORKSTREAMS.md Phase 2).

Wires the real parts of every workstream into one :class:`Daemon`:

- C: the platform backend (``pyvpn.platform.linux.backend.LinuxBackend``),
  or the development-only :class:`DryRunBackend`;
- D: :class:`NetlinkTargetWatcher`;
- E: :class:`AppManager` over :class:`CgroupManager`, plus the
  :class:`ProcessWatcher` that places matching processes as they start;
- F: :class:`PolicyDnsService` with upstream sockets bound by
  :func:`bound_dns_socket`, and :func:`audit_dns` for ``pyvpn audit``;
- G: :func:`matcher_factory` with the on-disk ASN cache (read on start and
  reload; :func:`watch_asn_cache` reports entries that go stale meanwhile);
- A: configuration loading.

If the Linux backend is not part of the installed package, the daemon refuses
to start (fail closed): it never runs as if it were routing when it is not.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import logging
import os
import signal
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

from pyvpn import __version__
from pyvpn.apps.cgroups import CgroupManager
from pyvpn.apps.manager import AppManager
from pyvpn.apps.watcher import Place, ProcessWatcher
from pyvpn.audit import audit_dns
from pyvpn.config import ConfigError, default_config_path, load_config
from pyvpn.config.models import Config
from pyvpn.constants import SOCKET_PATH, STATE_DIR
from pyvpn.daemon.core import Daemon
from pyvpn.daemon.dryrun import DryRunBackend, describe_policy
from pyvpn.daemon.persistence import StateError, StateStore
from pyvpn.daemon.server import ApiError
from pyvpn.dns.service import PolicyDnsService
from pyvpn.dns.upstream import BoundUpstream
from pyvpn.match.asn import REFRESH_HINT, AsnCache
from pyvpn.match.policy import PolicyMatcher, matcher_factory
from pyvpn.platform.base import Backend
from pyvpn.platform.linux.dns import bound_dns_socket
from pyvpn.platform.linux.netlink import NetlinkEventSource, NetlinkTargetWatcher

log = logging.getLogger("pyvpn.daemon")

BACKENDS = ("linux", "dry-run")
LINUX_BACKEND_MODULE = "pyvpn.platform.linux.backend"
LINUX_BACKEND_CLASS = "LinuxBackend"
SYSTEM_CGROUP_ROOT = Path("/sys/fs/cgroup")
ASN_CHECK_INTERVAL = 3600.0


class BackendUnavailable(RuntimeError):
    """The requested platform backend cannot be loaded."""


def load_backend(name: str, *, cgroup_root: Path | None = None) -> Backend:
    """Return the backend called ``name``; raise :class:`BackendUnavailable`."""
    if name == "dry-run":
        return DryRunBackend()
    if name != "linux":
        raise BackendUnavailable(f"unknown backend {name!r}; choose one of {', '.join(BACKENDS)}")
    try:
        module = importlib.import_module(LINUX_BACKEND_MODULE)
    except ImportError as exc:
        if isinstance(exc, ModuleNotFoundError) and exc.name == LINUX_BACKEND_MODULE:
            raise BackendUnavailable(
                "the Linux routing backend is not part of this build "
                f"({LINUX_BACKEND_MODULE} is missing), so nothing can be routed; refusing "
                "to start. Use --backend dry-run to run the daemon without routing."
            ) from exc
        missing = f" (missing module {exc.name!r})" if exc.name else ""
        raise BackendUnavailable(
            f"cannot load the Linux routing backend{missing}: {exc}; refusing to start"
        ) from exc
    backend_class = getattr(module, LINUX_BACKEND_CLASS, None)
    if backend_class is None:
        raise BackendUnavailable(f"{LINUX_BACKEND_MODULE} does not define {LINUX_BACKEND_CLASS}")
    backend: Backend = (
        backend_class() if cgroup_root is None else backend_class(cgroup_root=cgroup_root)
    )
    return backend


@dataclass(frozen=True)
class Options:
    config_path: Path
    socket_path: Path = Path(SOCKET_PATH)
    state_dir: Path = Path(STATE_DIR)
    backend: str = "linux"
    cgroup_root: Path | None = None  # None: /sys/fs/cgroup, or a scratch dir for dry-run
    process_watcher: bool | None = None  # None: on, except for dry-run

    @property
    def dry_run(self) -> bool:
        return self.backend == "dry-run"

    def resolved_cgroup_root(self) -> Path:
        if self.cgroup_root is not None:
            return self.cgroup_root
        # A dry run must not move real processes between cgroups.
        return self.state_dir / "cgroup-dry-run" if self.dry_run else SYSTEM_CGROUP_ROOT

    def watch_processes(self) -> bool:
        return (not self.dry_run) if self.process_watcher is None else self.process_watcher


class ProcessWatcherRunner:
    """Run one :class:`ProcessWatcher` for the committed config.

    The watcher's selectors come from the config, so it is replaced every time
    the daemon commits a config (startup and reload). The replacement scans
    ``/proc`` again, so no running app is missed across a reload.

    Placement goes through ``place`` (the daemon's :meth:`Daemon.place_trusted`),
    which refuses while a policy's rules are not installed (fail closed). A
    refused placement is retried by one more ``/proc`` scan after the next
    successful apply (:meth:`on_applied`), so apps found during a failed
    startup apply are placed once rules exist.
    """

    def __init__(self, place: Place, on_failure: Callable[[str], None] | None = None) -> None:
        self._place_pid = place
        self._on_failure = on_failure
        self._watcher: ProcessWatcher | None = None
        self._task: asyncio.Task[None] | None = None
        self._rescan: asyncio.Task[None] | None = None
        self._deferred = False

    def update(self, config: Config) -> None:
        self._stop_current()
        self._deferred = False
        watcher = ProcessWatcher(config.policies, self._place, groups=config.app_groups)
        self._watcher = watcher
        self._task = asyncio.ensure_future(self._run(watcher, self._on_failure))
        self._task.set_name("pyvpn-process-watcher")

    async def _place(self, pid: int, policy_id: int) -> None:
        # CgroupError / OSError (e.g. the process exited first) propagate to
        # ``ProcessWatcher._place``, which handles them per pid.
        try:
            await self._place_pid(pid, policy_id)
        except ApiError as exc:
            if exc.code != "unavailable":
                log.warning("not placing process %d in policy %d: %s", pid, policy_id, exc)
                return
            self._deferred = True
            log.debug("deferring process %d (policy %d): %s", pid, policy_id, exc)

    def on_applied(self) -> None:
        """Rescan once if a placement was refused before rules were installed."""
        watcher = self._watcher
        if not self._deferred or watcher is None:
            return
        if self._rescan is not None and not self._rescan.done():
            return
        self._deferred = False
        self._rescan = asyncio.ensure_future(self._scan(watcher))
        self._rescan.set_name("pyvpn-process-rescan")

    @staticmethod
    async def _scan(watcher: ProcessWatcher) -> None:
        try:
            moved = await watcher.scan()
        except Exception:
            log.exception("process rescan failed")
            return
        log.info("placed %d running processes after rules were installed", moved)

    @staticmethod
    async def _run(watcher: ProcessWatcher, on_failure: Callable[[str], None] | None) -> None:
        try:
            await watcher.run_proc_connector()
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("process watcher failed; new processes are no longer placed")
            reason = f"process watcher failed: {exc}"
        if on_failure is not None:
            on_failure(reason)

    def _stop_current(self) -> None:
        if self._watcher is not None:
            self._watcher.stop()
        for task in (self._task, self._rescan):
            if task is not None:
                task.cancel()

    async def close(self) -> None:
        tasks = [t for t in (self._task, self._rescan) if t is not None]
        self._stop_current()
        self._watcher = self._task = self._rescan = None
        await asyncio.gather(*tasks, return_exceptions=True)


@dataclass
class Assembly:
    """The daemon and the parts the composition root still owns."""

    daemon: Daemon
    backend: Backend
    dns: PolicyDnsService
    apps: AppManager
    process_watcher: ProcessWatcherRunner | None
    asn_cache: AsnCache | None = None

    async def close(self) -> None:
        if self.process_watcher is not None:
            await self.process_watcher.close()
        close = getattr(self.backend, "close", None)
        if close is not None:
            await close()  # background work only; installed rules stay


def build_daemon(
    options: Options,
    *,
    backend: Backend,
    config: Config | None = None,
    netlink: NetlinkEventSource | None = None,
) -> Assembly:
    """Build the daemon from the real parts. Opens state files, nothing else.

    ``config`` (the startup config) is loaded from ``options.config_path``
    when not given; the target watcher needs its targets up front, since
    reload cannot change targets or probe settings.
    """
    if config is None:
        config = load_config(options.config_path)
    state_dir = options.state_dir
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    apps = AppManager(CgroupManager(options.resolved_cgroup_root()))
    route_and_place = getattr(backend, "place_policy_pid", None)
    spawn_isolated = getattr(backend, "spawn_isolated", None)
    targets = NetlinkTargetWatcher(config.targets, netlink, settings=config.settings)

    daemon: Daemon | None = None
    # Only the daemon's own uid may have written the cache it routes by
    # (root in production), so other users cannot plant prefixes.
    asn_cache = AsnCache(state_dir / "asn", trusted_uids={os.geteuid()})

    def active_matcher() -> Any:
        # Late-bound: the DNS service is built before the daemon.
        if daemon is None:
            raise RuntimeError("daemon not built yet")
        return daemon.active_matcher()

    dns = PolicyDnsService(
        BoundUpstream(bound_dns_socket),
        alias_path=state_dir / "dns-aliases.sqlite3",
        matcher_factory=active_matcher,
    )

    async def audit() -> dict[str, Any]:
        if daemon is None:
            raise RuntimeError("daemon not built yet")
        return audit_report(daemon, dns, options.backend)

    daemon = Daemon(
        config_loader=lambda: load_config(options.config_path),
        backend=backend,
        targets=targets,
        apps=apps,
        dns=dns,
        matcher_factory=matcher_factory(asn_cache),
        audit=audit,
        place_policy_pid=(
            partial(route_and_place, apps.cgroups) if route_and_place is not None else None
        ),
        spawn_isolated=(
            partial(spawn_isolated, apps.cgroups) if spawn_isolated is not None else None
        ),
        store=StateStore(state_dir / "state.json"),
        socket_path=options.socket_path,
    )

    runner: ProcessWatcherRunner | None = None
    if options.watch_processes():
        # Through the daemon, never ``apps.place_pid`` directly: placement
        # must wait until the policy's rules are installed.
        runner = ProcessWatcherRunner(
            daemon.place_trusted,
            on_failure=lambda reason: daemon.report_watcher_error("processes", reason),
        )
        daemon.on_config = runner.update
        daemon.reconciler.on_applied = runner.on_applied
    return Assembly(
        daemon=daemon,
        backend=backend,
        dns=dns,
        apps=apps,
        process_watcher=runner,
        asn_cache=asn_cache,
    )


def asn_cache_problem(daemon: Daemon, cache: AsnCache) -> str:
    """Why the committed config's ``asn:`` prefixes are no longer backed by a
    usable cache entry; empty when they are.

    The prefixes already installed stay in force: dropping them would send
    those destinations out the default route. A reload refuses the stale
    entries (fail closed) until ``pyvpn asn refresh`` renews them.
    """
    config = daemon.reconciler.config
    if config is None:
        return ""
    errors = [
        e.error or f"asn:{e.asn} is {e.state}"
        for e in (cache.entry(a) for a in PolicyMatcher.from_config(config).asns())
        if not e.usable
    ]
    if not errors:
        return ""
    return (
        "ASN cache: " + "; ".join(errors) + "; the installed prefixes stay in force, "
        f"but a reload will refuse them: {REFRESH_HINT}"
    )


async def watch_asn_cache(
    daemon: Daemon, cache: AsnCache, interval: float = ASN_CHECK_INTERVAL
) -> None:
    """Report stale ASN cache entries in ``pyvpn status`` (``last error``)."""
    while True:
        try:
            problem = await asyncio.to_thread(asn_cache_problem, daemon, cache)
        except Exception as exc:
            problem = f"ASN cache check failed: {exc}"
        if problem:
            log.warning("%s", problem)
        daemon.report_watcher_error("asn", problem)  # "" clears it
        await asyncio.sleep(interval)


def audit_report(daemon: Daemon, dns: PolicyDnsService, backend_name: str) -> dict[str, Any]:
    """The ``audit`` API result: backend, enabled state and per-policy DNS checks."""
    reconciler = daemon.reconciler
    plan = reconciler.plan()
    names = [policy.name for policy in daemon.config.policies] if reconciler.config else []
    warnings: list[str] = []
    if backend_name == "dry-run":
        warnings.append("dry-run backend: no traffic is routed or blocked")
    if reconciler.last_error:
        warnings.append(reconciler.last_error)
    policies: list[str] = []
    dns_checks: dict[str, str] = {}
    for policy in plan.policies if plan is not None else ():
        pid = policy.policy_id
        name = names[pid - 1] if pid <= len(names) else str(pid)
        policies.append(f"{name}: {describe_policy(policy)}")
        result = audit_dns(policy, listening=dns.is_listening(pid))
        dns_checks[name] = result.upstream_problem or f"via {result.upstream_interface}"
    return {
        "enabled": reconciler.enabled,
        "backend": backend_name,
        "policies": policies,
        "dns": dns_checks,
        "warnings": warnings,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyvpn-daemon", description="pyvpn root daemon (per-process policy routing)"
    )
    parser.add_argument("--version", action="version", version=f"pyvpn-daemon {__version__}")
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="configuration JSON (default: $PYVPN_CONFIG or /etc/pyvpn/config.json)",
    )
    parser.add_argument("--socket", type=Path, default=Path(SOCKET_PATH), help="API socket path")
    parser.add_argument("--state-dir", type=Path, default=Path(STATE_DIR), help="state directory")
    parser.add_argument(
        "--backend",
        choices=BACKENDS,
        default="linux",
        help="routing backend; dry-run logs plans and routes NOTHING (development only)",
    )
    parser.add_argument(
        "--cgroup-root",
        type=Path,
        default=None,
        help="cgroup v2 mount (default /sys/fs/cgroup; a scratch dir with --backend dry-run)",
    )
    watcher = parser.add_mutually_exclusive_group()
    watcher.add_argument(
        "--process-watcher",
        dest="process_watcher",
        action="store_true",
        default=None,
        help="place matching processes as they start (default, except with dry-run)",
    )
    watcher.add_argument("--no-process-watcher", dest="process_watcher", action="store_false")
    parser.add_argument(
        "--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR")
    )
    return parser


def options_from_args(args: argparse.Namespace) -> Options:
    return Options(
        config_path=args.config if args.config is not None else default_config_path(),
        socket_path=args.socket,
        state_dir=args.state_dir,
        backend=args.backend,
        cgroup_root=args.cgroup_root,
        process_watcher=args.process_watcher,
    )


async def serve(assembly: Assembly) -> int:
    """Start the daemon, handle signals and wait until it stops."""
    daemon = assembly.daemon
    loop = asyncio.get_running_loop()
    pending: set[asyncio.Task[None]] = set()

    def later(coro: Any) -> None:
        task = asyncio.ensure_future(coro)
        pending.add(task)
        task.add_done_callback(pending.discard)

    async def reload() -> None:
        try:
            await daemon.reload()
            log.info("configuration reloaded")
        except Exception as exc:
            log.error("reload failed, previous configuration stays in force: %s", exc)

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: later(daemon.stop()))
    try:
        try:
            await daemon.start()
        except (ConfigError, ApiError, StateError, OSError) as exc:
            log.error("cannot start: %s", exc)
            return 1
        # Only now: a reload must not run concurrently with startup's install.
        loop.add_signal_handler(signal.SIGHUP, lambda: later(reload()))
        if assembly.asn_cache is not None:
            later(watch_asn_cache(daemon, assembly.asn_cache))
        await daemon.wait_stopped()
        return 0
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            loop.remove_signal_handler(sig)
        # Finish shutdown deterministically: no reload may still be applying.
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await assembly.close()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(levelname)s %(name)s: %(message)s")
    options = options_from_args(args)
    if options.dry_run and options.process_watcher:
        print(
            "pyvpn-daemon: --process-watcher cannot be used with --backend dry-run: "
            "dry-run cgroups are plain directories, so no process would actually move",
            file=sys.stderr,
        )
        return 2
    try:
        backend = load_backend(options.backend, cgroup_root=options.cgroup_root)
    except BackendUnavailable as exc:
        print(f"pyvpn-daemon: {exc}", file=sys.stderr)
        return 2
    if options.dry_run:
        log.warning("running with the dry-run backend: NO traffic is routed or blocked")
    try:
        assembly = build_daemon(options, backend=backend)
    except (ConfigError, OSError) as exc:
        print(f"pyvpn-daemon: {exc}", file=sys.stderr)
        return 1
    return asyncio.run(serve(assembly))


if __name__ == "__main__":
    raise SystemExit(main())
