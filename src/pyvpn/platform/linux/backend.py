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
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path

from pyvpn.apps.cgroups import CgroupError, CgroupManager
from pyvpn.constants import policy_cgroup
from pyvpn.netfilter.render import render
from pyvpn.netfilter.ruleset import (
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
CGROUP_ROOT = Path("/sys/fs/cgroup")


class NftError(RuntimeError):
    pass


async def run_nft(script: str) -> None:
    """Load ``script`` with ``nft -f -`` (one transaction)."""
    proc = await asyncio.create_subprocess_exec(
        "nft",
        "-f",
        "-",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate(script.encode())
    if proc.returncode != 0:
        raise NftError(f"nft failed ({proc.returncode}): {err.decode(errors='replace').strip()}")


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
        netlink: RouteNetlink | None = None,
        cgroup_root: Path = CGROUP_ROOT,
        proc_sys: Path = PROC_SYS,
        cgroup_poll: float = 0.5,
    ) -> None:
        self._nft = nft or run_nft
        self._routes = RouteManager(netlink or Pyroute2Netlink(proc_sys=proc_sys))
        self._cgroup_root = cgroup_root
        self._proc_sys = proc_sys
        self._cgroup_poll = cgroup_poll
        self._known_state = False
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
            for path in policy.apps.cgroup_paths:
                if not (self._cgroup_root / path.strip("/")).is_dir():
                    raise ValueError(f"policy {policy.policy_id}: cgroup {path!r} does not exist")

    def _cgroup_id(self, path: str) -> int | None:
        """The cgroup's id (its kernfs inode), or None when it does not exist."""
        try:
            return os.stat(self._cgroup_root / path.strip("/")).st_ino
        except OSError:
            return None

    def _plan_cgroups(self, plan: RoutingPlan) -> dict[str, int | None]:
        return {c: self._cgroup_id(c) for p in plan.policies for c in p.apps.cgroup_paths}

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
        routes = build_route_plan(plan)
        if not ipv6_available(self._proc_sys):
            routes = RoutePlan(
                tuple(r for r in routes.rules if r.version == 4),
                tuple(r for r in routes.routes if r.version == 4),
            )
        script = render(build_ruleset(plan))
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
        while True:
            await asyncio.sleep(self._cgroup_poll)
            try:
                await self.recheck_cgroups()
            except Exception:
                log.exception("re-apply after a cgroup change failed; retrying")

    async def recheck_cgroups(self) -> bool:
        """Re-apply the last plan if a cgroup it names was re-created.

        Waits while a named cgroup is missing (the apply would be refused);
        returns whether it re-applied.
        """
        async with self._lock:
            if self._plan is None:
                return False
            ids = self._plan_cgroups(self._plan)
            if None in ids.values() or ids == self._cgroup_ids:
                return False
            log.info("cgroup ids changed; re-applying the routing plan")
            await self._apply_locked(self._plan)
            return True

    async def _replace(self, routes: RoutePlan, script: str) -> None:
        previous = await asyncio.to_thread(self._routes.snapshot)
        guard = render(build_route_guard(enabled=True))
        release = render(build_route_guard(enabled=False))
        await self._nft(guard)
        try:
            await asyncio.to_thread(self._routes.sync, routes)
            await self._nft(script + release)
        except (Exception, asyncio.CancelledError):
            try:
                await asyncio.to_thread(self._routes.sync, previous)
                # On restart we may have inherited a guard from a failed apply.
                # Only a successful commit can establish that it is safe to lift.
                if self._known_state:
                    await self._nft(release)
                else:
                    log.warning("leaving the routing guard active until a plan is installed")
            except Exception:
                self._known_state = False
                log.exception("routing rollback failed; leaving the routing guard active")
            raise
        self._known_state = True

    async def add_to_set(self, dests: DestSet) -> None:
        script = render(build_set_update(dests))
        if script:
            async with self._lock:
                await _finish_transaction(self._nft(script))
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
            self._plan, self._cgroup_ids = None, {}
            await _finish_transaction(self._replace(RoutePlan((), ()), render(build_teardown())))
