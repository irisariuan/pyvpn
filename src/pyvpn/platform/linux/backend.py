"""Linux ``Backend``: nftables (``table inet pyvpn``) + policy routing tables.

``apply`` order, chosen so marked traffic never falls through to the host's
default route (fail closed):

1. Build everything (pure). An invalid plan raises before anything changes.
2. ``RouteManager.install``: every desired table gets its unreachable guard,
   then its device route, then the ``ip rule`` pointing at it. Nothing is
   removed yet, so the old nft table still works against these tables.
3. One ``nft -f -`` transaction deletes and re-creates ``table inet pyvpn``.
   nft either installs all of it or none of it. If it fails, the routes are
   put back to the previously applied plan and the error is raised.
4. ``RouteManager.prune`` removes routes and rules the plan no longer wants.
   Kill-switch policies are already rejected by the new nft rules at this
   point, so the order of removals cannot leak. If this step fails the
   error is raised; the daemon retries and every step is idempotent.

The ruleset is loaded as nft script text rendered from the JSON builder:
nft 1.0.9 cannot parse ``socket cgroupv2`` in JSON (see ``netfilter.render``).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path

from pyvpn.netfilter.render import render
from pyvpn.netfilter.ruleset import Json, build_ruleset, build_set_update, build_teardown
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
        self._installed: RoutePlan | None = None
        self._lock = asyncio.Lock()

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(transparent=True, per_app_dns=True)

    def _existing_cgroups(self, plan: RoutingPlan) -> RoutingPlan:
        """Drop cgroup paths that do not exist: nft refuses to load a rule
        naming one, and an absent cgroup holds no process to match."""
        policies = []
        for p in plan.policies:
            paths = tuple(
                c for c in p.apps.cgroup_paths if (self._cgroup_root / c.strip("/")).is_dir()
            )
            if paths != p.apps.cgroup_paths:
                missing = sorted(set(p.apps.cgroup_paths) - set(paths))
                log.warning("policy %d: skipping missing cgroups %s", p.policy_id, missing)
                p = replace(p, apps=replace(p.apps, cgroup_paths=paths))
            policies.append(p)
        return RoutingPlan(tuple(policies))

    async def apply(self, plan: RoutingPlan) -> None:
        async with self._lock:
            plan = self._existing_cgroups(plan)
            routes = build_route_plan(plan)
            script = render(build_ruleset(plan))

            await asyncio.to_thread(self._routes.install, routes)
            try:
                await self._nft(script)
            except BaseException:
                await self._rollback()
                raise
            await asyncio.to_thread(self._routes.prune, routes)
            self._installed = routes

    async def _rollback(self) -> None:
        """Put routes back to the last applied plan after a failed nft load.

        With no plan applied by this process, the rules ``install`` added are
        left in place: removing rules a previous daemon installed would let
        its still-loaded nft marks fall through to the default route.
        """
        if self._installed is None:
            return
        try:
            await asyncio.to_thread(self._routes.sync, self._installed)
        except Exception:
            log.exception("could not restore the previous routes")

    async def add_to_set(self, dests: DestSet) -> None:
        doc: Json = build_set_update(dests)
        if doc["nftables"]:
            await self._nft(render(doc))

    async def teardown(self) -> None:
        async with self._lock:
            # Stop marking first, then drop the rules and tables.
            await self._nft(render(build_teardown()))
            await asyncio.to_thread(self._routes.teardown)
            self._installed = None
