"""Linux ``Backend``: nftables (``table inet pyvpn``) + policy routing tables.

Route and nft changes are separate kernel transactions. Keep the old nft
classifier and reject marked output while preparing routes. The final nft
transaction replaces the classifier and removes the guard together. If route
preparation or the final nft transaction fails, restore the prior routes while
marked output is still guarded.

Kept in sync without the daemon:

* ``socket cgroupv2`` rules hold the cgroup *id* nft resolved at load time.
  The backend re-applies the last plan, including learned destinations,
  before placing a PID into a recreated policy cgroup. A background check
  also reloads changed IDs for cgroups recreated outside that placement path.
* ``net.ipv4.conf.all.src_valid_mark`` is turned on (as ``wg-quick`` does)
  so strict ``rp_filter`` validates replies with their restored mark. It is
  left on at teardown, since other tunnels may rely on it too.
* On a kernel without IPv6 (``ipv6.disable=1``) only IPv4 rules and routes
  are installed; such a host has no IPv6 traffic to leak.

The ruleset is loaded as nft script text rendered from the JSON builder:
nft 1.0.9 cannot parse ``socket cgroupv2`` in JSON (see ``netfilter.render``).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path

from pyvpn.apps.cgroups import CgroupError, CgroupManager
from pyvpn.constants import CGROUP_ROOT as CGROUP_SLICE
from pyvpn.constants import NFT_TABLE, parse_excluded_cgroup, policy_cgroup
from pyvpn.netfilter.render import render
from pyvpn.netfilter.ruleset import (
    FAMILY,
    ROUTE_GUARD_TABLE,
    build_route_guard,
    build_ruleset,
    build_set_update,
    build_teardown,
)
from pyvpn.platform.base import Capabilities
from pyvpn.routing.apply import (
    PROC_SYS,
    Pyroute2Netlink,
    RouteManager,
    RouteNetlink,
    ipv6_available,
)
from pyvpn.routing.plan import RoutePlan, build_route_plan
from pyvpn.state import DestSet, RoutingPlan

log = logging.getLogger(__name__)

NftRunner = Callable[[str], Awaitable[None]]
NftTables = Callable[[], Awaitable[set[str]]]
CGROUP_ROOT = Path("/sys/fs/cgroup")
_NFT_TIMEOUT = 10.0
_NFT_EXIT_GRACE = 1.0


class NftError(RuntimeError):
    pass


class NftOutcomeUnknown(NftError):
    """The nft command stopped responding or exited without an acknowledgement."""

    def __init__(self, message: str, process: asyncio.subprocess.Process | None = None) -> None:
        super().__init__(message)
        self.process = process


class _NftCommitUnconfirmed(NftError):
    """Read-back could not prove whether it is safe to restore the old routes."""


async def run_nft(script: str) -> None:
    """Load ``script`` with ``nft -f -`` (one transaction)."""
    await _nft_command("-f", "-", data=script.encode())


def _consume_nft_result(task: asyncio.Task[tuple[bytes, bytes]]) -> None:
    if not task.cancelled():
        task.exception()


async def _nft_command(*args: str, data: bytes | None = None) -> bytes:
    proc = await asyncio.create_subprocess_exec(
        "nft",
        *args,
        stdin=asyncio.subprocess.PIPE if data is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    communication = asyncio.create_task(proc.communicate(data))
    try:
        async with asyncio.timeout(_NFT_TIMEOUT):
            out, err = await asyncio.shield(communication)
    except (Exception, asyncio.CancelledError) as exc:
        # Keep draining the pipes while the killed process exits. Bound the
        # cleanup too, since the process may still be blocked in the kernel.
        communication.add_done_callback(_consume_nft_result)
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        except OSError:
            log.exception("could not terminate nft after losing its response")
        await asyncio.wait((communication,), timeout=_NFT_EXIT_GRACE)
        if isinstance(exc, asyncio.CancelledError):
            raise
        detail = f"timed out after {_NFT_TIMEOUT:g}s" if isinstance(exc, TimeoutError) else str(exc)
        raise NftOutcomeUnknown(f"nft {' '.join(args)}: {detail}", proc) from exc

    code = proc.returncode
    assert code is not None
    if code < 0:
        raise NftOutcomeUnknown(f"nft terminated by signal {-code}", proc)
    if code:
        raise NftError(f"nft failed ({code}): {err.decode(errors='replace').strip()}")
    return out


async def _list_nft_tables() -> set[str]:
    entries = json.loads(await _nft_command("-j", "list", "tables"))["nftables"]
    if not isinstance(entries, list):
        raise NftError("nft returned an invalid table list")
    return {
        entry["table"]["name"]
        for entry in entries
        if "metainfo" not in entry and entry["table"]["family"] == FAMILY
    }


async def _finish_transaction(operation: Awaitable[None]) -> None:
    """Wait for a transaction to settle before delivering caller cancellation."""
    transaction = asyncio.ensure_future(operation)
    cancelled = False
    try:
        while not transaction.done():
            try:
                await asyncio.shield(transaction)
            except asyncio.CancelledError:
                cancelled = True
        transaction.result()
    finally:
        if cancelled and not transaction.cancelled():
            caller = asyncio.current_task()
            assert caller is not None
            # Let the caller record a successful commit before its next await.
            asyncio.get_running_loop().call_soon(caller.cancel)


class LinuxBackend:
    def __init__(
        self,
        *,
        nft: NftRunner | None = None,
        nft_tables: NftTables | None = None,
        netlink: RouteNetlink | None = None,
        cgroup_root: Path = CGROUP_ROOT,
        proc_sys: Path = PROC_SYS,
        cgroup_poll: float = 0.5,
    ) -> None:
        self._nft = nft or run_nft
        self._nft_tables = nft_tables or _list_nft_tables
        self._routes = RouteManager(netlink or Pyroute2Netlink(proc_sys=proc_sys))
        self._cgroup_root = cgroup_root
        self._proc_sys = proc_sys
        self._cgroup_poll = cgroup_poll
        self._known_state = False
        self._needs_recovery = False
        self._exiting_nft: asyncio.subprocess.Process | None = None
        # Last applied plan plus destinations added since, and the ids of the
        # cgroups it names as recorded just before nft resolved them.
        self._plan: RoutingPlan | None = None
        self._cgroup_ids: dict[str, int | None] = {}
        self._watch: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(transparent=True, per_app_dns=True)

    def _require_cgroups(self, plan: RoutingPlan) -> None:
        for policy in plan.policies:
            for path in (*policy.apps.cgroup_paths, *policy.apps.exclude_cgroup_paths):
                if not (self._cgroup_root / path.strip("/")).is_dir():
                    raise ValueError(f"policy {policy.policy_id}: cgroup {path!r} does not exist")

    def _cgroup_id(self, path: str) -> int | None:
        """The cgroup's id (its kernfs inode), or None when it does not exist."""
        try:
            return os.stat(self._cgroup_root / path.strip("/")).st_ino
        except OSError:
            return None

    def _plan_cgroups(self, plan: RoutingPlan) -> dict[str, int | None]:
        paths = [
            c for p in plan.policies for c in (*p.apps.cgroup_paths, *p.apps.exclude_cgroup_paths)
        ]
        return {c: self._cgroup_id(c) for c in [*paths, *self._idle_exclusions(paths)]}

    def _idle_exclusions(self, listed: list[str]) -> list[str]:
        """Existing top-level ``x-<hex>`` cgroups that no binding lists.

        The app manager withholds them while it revalidates their members
        (PLAN.md §3.3). They must be known to the stale-cgroup check, or
        their members would be rejected instead of governed normally.
        """
        try:
            names = sorted(
                e.name for e in os.scandir(self._cgroup_root / CGROUP_SLICE) if e.is_dir()
            )
        except OSError:
            return []
        found = (f"{CGROUP_SLICE}/{name}" for name in names)
        return [
            path
            for path in found
            if path not in listed
            and (decoded := parse_excluded_cgroup(path)) is not None
            and decoded.app_policy_id is None
        ]

    def _enable_src_valid_mark(self) -> None:
        knob = self._proc_sys / "net/ipv4/conf/all/src_valid_mark"
        try:
            if knob.read_text().strip() != "1":
                knob.write_text("1\n")
                log.info("enabled net.ipv4.conf.all.src_valid_mark for strict rp_filter")
        except OSError as e:
            log.warning("could not enable src_valid_mark; strict rp_filter may drop replies: %s", e)

    async def apply(self, plan: RoutingPlan) -> None:
        async with self._lock:
            await self._apply_locked(plan)
        self._start_watch()

    async def _apply_locked(self, plan: RoutingPlan) -> None:
        # Record ids before nft resolves the paths: a cgroup re-created in
        # between then shows up as changed and is re-applied.
        ids = self._plan_cgroups(plan)
        self._require_cgroups(plan)
        listed = {c for p in plan.policies for c in p.apps.exclude_cgroup_paths}
        idle = [c for c in ids if c not in listed and parse_excluded_cgroup(c) is not None]
        routes = build_route_plan(plan)
        if not ipv6_available(self._proc_sys):
            routes = RoutePlan(
                tuple(r for r in routes.rules if r.version == 4),
                tuple(r for r in routes.routes if r.version == 4),
            )
        script = render(build_ruleset(plan, idle_exclusions=idle))
        self._enable_src_valid_mark()
        await _finish_transaction(self._replace(routes, script))
        self._plan, self._cgroup_ids = plan, ids

    async def place_policy_pid(
        self, cgroups: CgroupManager, pid: int, policy_id: int, verify_peer: Callable[[], None]
    ) -> None:
        """Move a PID only after its exact cgroup is governed by installed rules."""
        path = policy_cgroup(policy_id)
        async with self._lock:
            plan = self._plan
            if plan is None or path not in self._cgroup_ids:
                raise CgroupError(f"routing rules for {path} are not installed")

            installed_id = self._cgroup_ids[path]
            if (
                not self._known_state
                or installed_id is None
                or self._cgroup_id(path) != installed_id
            ):
                # Recreate every missing pyvpn-managed child so recovery also
                # works when the entire slice disappeared. Leave external
                # cgroups to their owners, as in a normal apply.
                for policy in plan.policies:
                    child = policy_cgroup(policy.policy_id)
                    if child in self._cgroup_ids and self._cgroup_id(child) is None:
                        cgroups.create(policy.policy_id)
                try:
                    await self._apply_locked(plan)
                except Exception as exc:
                    raise CgroupError(
                        f"could not reinstall routing rules for {path}: {exc}"
                    ) from exc
                await asyncio.sleep(0)  # deliver any cancellation deferred by the transaction
                installed_id = self._cgroup_ids[path]
                if installed_id is None:
                    raise CgroupError(f"routing rules for {path} are not installed")

            verify_peer()
            cgroups.place_pid(pid, policy_id, installed_id=installed_id)

    def _start_watch(self) -> None:
        if self._watch is None or self._watch.done():
            self._watch = asyncio.get_running_loop().create_task(self._watch_cgroups())

    async def _watch_cgroups(self) -> None:
        failed = False
        while True:
            await asyncio.sleep(self._cgroup_poll)
            try:
                await self.recheck_cgroups()
            except Exception:
                if not failed:
                    log.exception("routing recovery failed; retrying")
                failed = True
            else:
                failed = False

    async def recheck_cgroups(self) -> bool:
        """Re-apply the last plan after a cgroup change or nft recovery failure.

        Waits while a named cgroup is missing (the apply would be refused);
        returns whether it re-applied.
        """
        async with self._lock:
            if self._plan is None:
                return False
            ids = self._plan_cgroups(self._plan)
            if None in ids.values() or (ids == self._cgroup_ids and not self._needs_recovery):
                return False
            await self._apply_locked(self._plan)
            log.info("re-applied the routing plan after a cgroup change or nft failure")
            return True

    def _require_nft_idle(self) -> None:
        if self._exiting_nft is not None and self._exiting_nft.returncode is None:
            raise NftError("a terminated nft command is still exiting")
        self._exiting_nft = None

    async def _run_nft(self, script: str) -> None:
        self._require_nft_idle()
        try:
            await self._nft(script)
        except NftOutcomeUnknown as exc:
            self._exiting_nft = exc.process
            raise

    async def _commit(self, script: str, *, expect_table: bool) -> None:
        try:
            await self._run_nft(script)
        except asyncio.CancelledError as exc:
            raise _NftCommitUnconfirmed("nft transaction interrupted before confirmation") from exc
        except NftOutcomeUnknown as exc:
            try:
                self._require_nft_idle()
                tables = await self._nft_tables()
            except (Exception, asyncio.CancelledError) as probe_error:
                if isinstance(probe_error, NftOutcomeUnknown):
                    self._exiting_nft = probe_error.process
                raise _NftCommitUnconfirmed(
                    f"{exc}; could not verify nft transaction: {probe_error}"
                ) from probe_error

            # Installation of the guard was acknowledged. Only the final
            # atomic batch removes it, so its presence means rollback is safe.
            if ROUTE_GUARD_TABLE in tables:
                raise
            if (NFT_TABLE in tables) != expect_table:
                raise _NftCommitUnconfirmed(
                    f"{exc}; nft tables did not match either transaction outcome"
                ) from exc
            log.warning("%s; the kernel confirms the nft transaction committed", exc)

    async def _replace(self, routes: RoutePlan, script: str, *, expect_table: bool = True) -> None:
        previous = await asyncio.to_thread(self._routes.snapshot)
        guard = render(build_route_guard(enabled=True))
        release = render(build_route_guard(enabled=False))
        try:
            await self._run_nft(guard)
        except NftOutcomeUnknown:
            self._known_state = False
            self._needs_recovery = True
            raise
        try:
            await asyncio.to_thread(self._routes.sync, routes)
            await self._commit(script + release, expect_table=expect_table)
        except _NftCommitUnconfirmed:
            # New routes match a committed classifier. An uncommitted
            # classifier still has the guard. Reapplying under a fresh guard
            # can recover either state without mixing old routes and new rules.
            self._known_state = False
            self._needs_recovery = True
            raise
        except (Exception, asyncio.CancelledError):
            try:
                await asyncio.to_thread(self._routes.sync, previous)
                # On restart we may have inherited a guard from a failed apply.
                # Only a successful commit can establish that it is safe to lift.
                if self._known_state:
                    await self._run_nft(release)
                else:
                    log.warning("leaving the routing guard active until a plan is installed")
            except Exception:
                self._known_state = False
                self._needs_recovery = True
                log.exception("routing rollback failed; routing must be re-applied")
            raise
        self._known_state = True
        self._needs_recovery = False

    async def add_to_set(self, dests: DestSet) -> None:
        script = render(build_set_update(dests))
        if script:
            async with self._lock:
                if self._needs_recovery:
                    raise NftError("routing must be re-applied before publishing destinations")
                await _finish_transaction(self._run_nft(script))
                if self._plan is not None:
                    # Keep them for a backend-initiated re-apply (cgroup change).
                    self._plan = RoutingPlan(
                        tuple(
                            replace(p, dests=p.dests | dests)
                            if p.policy_id == dests.policy_id and p.dests is not None
                            else p
                            for p in self._plan.policies
                        )
                    )

    async def teardown(self) -> None:
        if self._watch is not None:
            self._watch.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._watch
            self._watch = None
        async with self._lock:
            await _finish_transaction(
                self._replace(RoutePlan((), ()), render(build_teardown()), expect_table=False)
            )
            self._plan, self._cgroup_ids = None, {}
