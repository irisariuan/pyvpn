"""Linux ``Backend``: nftables (``table inet pyvpn``) + policy routing tables.

Route and nft changes are separate kernel transactions. Keep the old nft
classifier and reject marked output while preparing routes. The final nft
transaction replaces the classifier and removes the guard together. If route
preparation or the final nft transaction fails, restore the prior routes while
marked output is still guarded.

The ruleset is loaded as nft script text rendered from the JSON builder:
nft 1.0.9 cannot parse ``socket cgroupv2`` in JSON (see ``netfilter.render``).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from pyvpn.netfilter.render import render
from pyvpn.netfilter.ruleset import (
    build_route_guard,
    build_ruleset,
    build_set_update,
    build_teardown,
)
from pyvpn.platform.base import Capabilities
from pyvpn.routing.apply import Pyroute2Netlink, RouteManager, RouteNetlink
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
    ) -> None:
        self._nft = nft or run_nft
        self._routes = RouteManager(netlink or Pyroute2Netlink())
        self._cgroup_root = cgroup_root
        self._known_state = False
        self._lock = asyncio.Lock()

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(transparent=True, per_app_dns=True)

    def _require_cgroups(self, plan: RoutingPlan) -> None:
        for policy in plan.policies:
            for path in policy.apps.cgroup_paths:
                if not (self._cgroup_root / path.strip("/")).is_dir():
                    raise ValueError(f"policy {policy.policy_id}: cgroup {path!r} does not exist")

    async def apply(self, plan: RoutingPlan) -> None:
        async with self._lock:
            self._require_cgroups(plan)
            routes = build_route_plan(plan)
            script = render(build_ruleset(plan))
            await _finish_transaction(self._replace(routes, script))

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

    async def teardown(self) -> None:
        async with self._lock:
            await _finish_transaction(self._replace(RoutePlan((), ()), render(build_teardown())))
