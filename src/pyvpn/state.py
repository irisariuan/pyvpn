"""Runtime data passed between workstreams (Phase 0 contract).

See WORKSTREAMS.md "The data that flows between streams".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Literal, TypeAlias

from pyvpn.config.models import LeakSettings

IPAddress: TypeAlias = IPv4Address | IPv6Address
RouteKind: TypeAlias = Literal["dev", "unreachable", "main"]


@dataclass(frozen=True)
class TargetStatus:
    """Produced by D (targets)."""

    name: str
    interface: str | None
    ifindex: int | None
    usable: bool
    gateways: tuple[IPAddress, ...] = ()
    addresses: tuple[IPAddress, ...] = ()


@dataclass(frozen=True)
class AppBinding:
    """Produced by E (apps).

    ``any_process`` is True for a policy with destination rules and no apps,
    which applies to every process (PLAN.md §3.4). An empty binding with
    ``any_process`` False matches nothing.
    """

    policy_id: int
    cgroup_paths: tuple[str, ...] = ()
    uids: tuple[int, ...] = ()
    any_process: bool = False


@dataclass(frozen=True)
class DestSet:
    """Produced by F (DNS answers) and G (asn:/cidr:)."""

    policy_id: int
    v4: frozenset[IPv4Network] = field(default_factory=frozenset)
    v6: frozenset[IPv6Network] = field(default_factory=frozenset)

    def __or__(self, other: DestSet) -> DestSet:
        if other.policy_id != self.policy_id:
            raise ValueError("cannot merge DestSets of different policies")
        return DestSet(self.policy_id, self.v4 | other.v4, self.v6 | other.v6)

    def __bool__(self) -> bool:
        return bool(self.v4 or self.v6)


@dataclass(frozen=True)
class PolicyPlan:
    """Computed by B (daemon), consumed by C / platform backends."""

    policy_id: int
    mark: int
    table: int
    rule_pref: int
    route: RouteKind
    interface: str | None
    gateways: tuple[IPAddress, ...]
    apps: AppBinding
    dests: DestSet | None  # None = all destinations
    leak: LeakSettings
    dns_stub_port: int | None
    target: str | None = None  # config name of the active target, for status


@dataclass(frozen=True)
class RoutingPlan:
    """The whole desired state, applied atomically."""

    policies: tuple[PolicyPlan, ...] = ()
