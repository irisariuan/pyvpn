"""Compile Linux policy rules and table entries without opening netlink."""

from dataclasses import dataclass
from typing import Literal

from pyvpn.constants import FWMARK_MASK, MAX_POLICIES, policy_mark, policy_rule_pref, policy_table
from pyvpn.state import IPAddress, PolicyPlan, RoutingPlan

IPVersion = Literal[4, 6]

# The shared mask identifies the tag. Individual rules also match the policy ID.
POLICY_MARK_MASK = FWMARK_MASK | ((1 << MAX_POLICIES.bit_length()) - 1)
TARGET_METRIC = 100
UNREACHABLE_METRIC = 32760


@dataclass(frozen=True)
class Rule:
    version: IPVersion
    priority: int
    mark: int
    mask: int
    table: int


@dataclass(frozen=True)
class DefaultRoute:
    version: IPVersion
    table: int
    metric: int
    kind: Literal["unicast", "unreachable"]
    interface: str | None = None
    gateway: IPAddress | None = None


@dataclass(frozen=True)
class RoutePlan:
    rules: tuple[Rule, ...]
    routes: tuple[DefaultRoute, ...]


def validate_policy(policy: PolicyPlan) -> None:
    policy_id = policy.policy_id
    if (policy.mark, policy.table, policy.rule_pref) != (
        policy_mark(policy_id),
        policy_table(policy_id),
        policy_rule_pref(policy_id),
    ):
        raise ValueError(f"policy {policy_id}: mark, table or priority outside its reserved slot")
    if policy.apps.policy_id != policy_id or (
        policy.dests is not None and policy.dests.policy_id != policy_id
    ):
        raise ValueError(
            f"policy {policy_id}: app binding or destination set belongs to another policy"
        )
    if policy.route == "dev" and not policy.interface:
        raise ValueError(f"policy {policy_id}: device route requires an interface")


def build_route_plan(plan: RoutingPlan) -> RoutePlan:
    """Describe the desired rules and routes for pyvpn's tables.

    Each managed family has a device-independent unreachable default installed
    alongside its preferred route. The device route can vanish on link removal
    while the guard remains. Explicit main fallback omits a pyvpn routing
    rule for each unblocked family so the host's normal rules can run.
    """
    rules: list[Rule] = []
    routes: list[DefaultRoute] = []
    seen: set[int] = set()
    for policy in plan.policies:
        validate_policy(policy)
        if policy.policy_id in seen:
            raise ValueError(f"duplicate policy {policy.policy_id}")
        seen.add(policy.policy_id)

        versions: tuple[IPVersion, ...] = (4, 6)
        for version in versions:
            if not _needs_table(policy, version):
                continue

            rules.append(
                Rule(version, policy.rule_pref, policy.mark, POLICY_MARK_MASK, policy.table)
            )
            routes.append(DefaultRoute(version, policy.table, UNREACHABLE_METRIC, "unreachable"))
            if (
                policy.route == "dev"
                and (version == 4 or policy.leak.ipv6 == "route")
                and (policy.gateway is None or policy.gateway.version == version)
            ):
                routes.append(
                    DefaultRoute(
                        version,
                        policy.table,
                        TARGET_METRIC,
                        "unicast",
                        policy.interface,
                        policy.gateway,
                    )
                )

    return RoutePlan(tuple(rules), tuple(routes))


def _needs_table(policy: PolicyPlan, version: IPVersion) -> bool:
    if policy.route == "unreachable":
        return True
    if version == 6:
        if policy.leak.ipv6 == "block":
            return True
        if policy.leak.ipv6 == "off":
            return False
    return policy.route == "dev"
