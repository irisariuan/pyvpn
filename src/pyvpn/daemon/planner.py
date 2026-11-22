"""Pure planning: config + runtime state -> RoutingPlan.

No I/O. Everything that decides *where* a policy's traffic goes lives here so
it can be tested exhaustively (PLAN.md §3.1-3.2, §5 ``on_down``).

Fail-closed rules:

* A target is used only if its status is known, ``usable`` and has an
  interface. Unknown (no event yet) counts as down.
* With no usable target, ``on_down: block`` gives ``unreachable`` and
  ``on_down: default`` gives ``main``.
* A policy with destination rules whose set is still empty routes nothing
  through the target (empty set, never ``None`` = "all destinations").
* A policy with ``drop:`` rules always gets a drop set (empty until DNS
  answers or ``drop:cidr:`` / ``drop:asn:`` fill it), so DNS-learned drop
  addresses always have somewhere to go.
"""

from __future__ import annotations

from collections.abc import Mapping

from pyvpn.config.models import Config, Policy
from pyvpn.constants import dns_stub_port, policy_mark, policy_rule_pref, policy_table
from pyvpn.state import AppBinding, DestSet, PolicyPlan, RoutingPlan, TargetStatus


def choose_target(
    policy: Policy, statuses: Mapping[str, TargetStatus]
) -> tuple[str, TargetStatus] | None:
    """First usable target in the policy's priority order, or None."""
    for name in policy.targets:
        st = statuses.get(name)
        if st is not None and st.usable and st.interface:
            return name, st
    return None


def default_binding(policy_id: int, policy: Policy) -> AppBinding:
    """Binding to use before the app manager has reported one."""
    return AppBinding(policy_id=policy_id, any_process=not policy.apps)


def has_drop_rules(policy: Policy) -> bool:
    """Whether the policy's destination rules include ``drop:`` rules."""
    return any(d.lstrip().lower().startswith("drop:") for d in policy.domains)


def plan_policy(
    policy_id: int,
    policy: Policy,
    config: Config,
    statuses: Mapping[str, TargetStatus],
    binding: AppBinding | None,
    dests: DestSet | None,
    drops: DestSet | None = None,
) -> PolicyPlan:
    chosen = choose_target(policy, statuses)
    if chosen is not None:
        name, st = chosen
        gateway = st.gateway
        if gateway is None:
            cfg = next(t for t in config.targets if t.name == name)
            if cfg.gateway not in (None, "auto"):
                gateway = cfg.gateway  # type: ignore[assignment]
        route, interface, target = "dev", st.interface, name
    else:
        gateway, interface, target = None, None, None
        route = "unreachable" if policy.on_down == "block" else "main"

    if policy.domains and policy.isolation != "netns":
        # An isolated policy's domains are only drop: rules (the daemon
        # refuses others): it governs every destination.
        plan_dests: DestSet | None = dests if dests is not None else DestSet(policy_id)
    else:
        plan_dests = None
    if has_drop_rules(policy):
        plan_drops: DestSet | None = drops if drops is not None else DestSet(policy_id, drop=True)
    else:
        plan_drops = None

    return PolicyPlan(
        policy_id=policy_id,
        mark=policy_mark(policy_id),
        table=policy_table(policy_id),
        rule_pref=policy_rule_pref(policy_id),
        route=route,  # type: ignore[arg-type]
        interface=interface,
        gateway=gateway,
        apps=binding if binding is not None else default_binding(policy_id, policy),
        dests=plan_dests,
        leak=policy.leak,
        dns_stub_port=dns_stub_port(policy_id) if policy.leak.dns_via_target else None,
        target=target,
        drops=plan_drops,
        isolation=policy.isolation,
    )


def build_plan(
    config: Config,
    statuses: Mapping[str, TargetStatus],
    bindings: Mapping[int, AppBinding],
    dests: Mapping[int, DestSet],
    drops: Mapping[int, DestSet] | None = None,
) -> RoutingPlan:
    drops = drops or {}
    return RoutingPlan(
        tuple(
            plan_policy(pid, p, config, statuses, bindings.get(pid), dests.get(pid), drops.get(pid))
            for pid, p in enumerate(config.policies, start=1)
        )
    )
