"""A backend that logs routing plans instead of installing them.

For development only (``pyvpn-daemon --backend dry-run``): it lets the daemon,
CLI, DNS stubs and target watcher run end to end without root or a Linux
routing backend. It routes and blocks **nothing**, so it must never be the
default.
"""

from __future__ import annotations

import logging

from pyvpn.platform.base import Capabilities
from pyvpn.state import DestSet, PolicyPlan, RoutingPlan

log = logging.getLogger(__name__)


def describe_policy(policy: PolicyPlan) -> str:
    """One log line for a policy plan."""
    if policy.route == "dev":
        route = f"dev {policy.interface}" + (f" via {policy.gateway}" if policy.gateway else "")
    else:
        route = policy.route
    apps = policy.apps
    if apps.any_process:
        who = "any process"
    else:
        parts = [*apps.cgroup_paths, *(f"uid {uid}" for uid in apps.uids)]
        who = ", ".join(parts) or "no apps"
    dests = (
        "all destinations"
        if policy.dests is None
        else f"{len(policy.dests.v4)} v4 / {len(policy.dests.v6)} v6 destinations"
    )
    return (
        f"policy {policy.policy_id} (target {policy.target or '-'}): {route}; "
        f"apps: {who}; {dests}; mark {policy.mark:#x} table {policy.table}"
    )


class DryRunBackend:
    """``pyvpn.platform.base.Backend`` that only records and logs."""

    def __init__(self) -> None:
        self.installed: RoutingPlan | None = None
        self.applies = 0

    @property
    def capabilities(self) -> Capabilities:
        # It enforces nothing, so it claims no capability.
        return Capabilities()

    async def apply(self, plan: RoutingPlan) -> None:
        self.applies += 1
        self.installed = plan
        log.warning("dry-run backend: NOT installing plan with %d policies", len(plan.policies))
        for policy in plan.policies:
            log.info("dry-run backend: %s", describe_policy(policy))

    async def add_to_set(self, dests: DestSet) -> None:
        log.info(
            "dry-run backend: policy %d learned %d v4 / %d v6 %s",
            dests.policy_id,
            len(dests.v4),
            len(dests.v6),
            "drop addresses" if dests.drop else "destinations",
        )

    async def teardown(self) -> None:
        self.installed = None
        log.warning("dry-run backend: teardown (nothing was installed)")
