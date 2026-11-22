"""Runtime data passed between workstreams (Phase 0 contract).

See WORKSTREAMS.md "The data that flows between streams".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Literal, TypeAlias

from pyvpn.config.models import LeakSettings
from pyvpn.constants import policy_cgroup

IPAddress: TypeAlias = IPv4Address | IPv6Address
RouteKind: TypeAlias = Literal["dev", "unreachable", "main"]


@dataclass(frozen=True)
class TargetStatus:
    """Produced by D (targets)."""

    name: str
    interface: str | None
    ifindex: int | None
    usable: bool
    gateway: IPAddress | None = None
    addresses: tuple[IPAddress, ...] = ()


@dataclass(frozen=True)
class AppBinding:
    """Produced by E (apps).

    ``any_process`` is True for a policy with destination rules and no apps,
    which applies to every process (PLAN.md §3.4). An empty binding with
    ``any_process`` False matches nothing.

    An ``any_process`` binding may also carry the policy's own placement
    cgroup (``pyvpn.slice/p-<id>``) in ``cgroup_paths``, so ``pyvpn run``
    works for destination-only policies; any other ``cgroup_paths`` entry,
    or any ``uids``, is rejected as ambiguous.

    ``exclude_cgroup_paths`` and ``exclude_uids`` exempt processes from an
    ``any_process`` binding: a socket in one of those cgroups (or below it),
    or owned by one of those uids, is not matched by this policy. They come
    from the policy's ``exclude_apps`` (PLAN.md §3.3), for example a
    userspace VPN client whose server address is in the policy's
    destination set. They are only valid with ``any_process``; for a policy
    with apps, the app manager applies exclusions by not placing the
    excluded processes in the policy's cgroup.

    Backends must test exclusions with *positive* matches (a socket in an
    excluded cgroup or owned by an excluded uid skips the policy) and let
    every other socket continue through normal policy handling. A negated
    ``socket cgroupv2 level N != ...`` does not match a socket that has no
    ancestor at depth N, which would leave that socket ungoverned.

    Exclusion paths are canonical cgroup paths relative to the cgroup2 root:
    no leading or trailing ``/``, no empty, ``.`` or ``..`` components, no
    whitespace, no duplicates. ``exclude_uids`` are distinct uids in
    ``0..4294967294``.
    """

    policy_id: int
    cgroup_paths: tuple[str, ...] = ()
    uids: tuple[int, ...] = ()
    any_process: bool = False
    exclude_cgroup_paths: tuple[str, ...] = ()
    exclude_uids: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if (self.exclude_cgroup_paths or self.exclude_uids) and not self.any_process:
            raise ValueError("exclusions are only valid on an any_process binding")
        if self.any_process:
            if self.uids:
                raise ValueError("an any_process binding must not list uids")
            if self.cgroup_paths and self.cgroup_paths != (policy_cgroup(self.policy_id),):
                raise ValueError("an any_process binding may only list its own policy cgroup")
        if len(set(self.exclude_cgroup_paths)) != len(self.exclude_cgroup_paths):
            raise ValueError("exclude_cgroup_paths must not contain duplicates")
        for path in self.exclude_cgroup_paths:
            _check_cgroup_path(path)
        if len(set(self.exclude_uids)) != len(self.exclude_uids):
            raise ValueError("exclude_uids must not contain duplicates")
        for uid in self.exclude_uids:
            if isinstance(uid, bool) or not isinstance(uid, int) or not 0 <= uid <= _UID_MAX:
                raise ValueError(f"exclude_uids entry {uid!r} is not a uid in 0..{_UID_MAX}")


_UID_MAX = 4294967294  # (uid_t)-1 is reserved


def _check_cgroup_path(path: str) -> None:
    if not path or not path.strip():
        raise ValueError("exclude_cgroup_paths must not contain an empty path")
    if any(ch.isspace() for ch in path):
        raise ValueError(f"exclude_cgroup_paths entry {path!r} contains whitespace")
    if path.startswith("/") or path.endswith("/"):
        raise ValueError(f"exclude_cgroup_paths entry {path!r} must not start or end with '/'")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError(f"exclude_cgroup_paths entry {path!r} has an invalid component")


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
    gateway: IPAddress | None
    apps: AppBinding
    dests: DestSet | None  # None = all destinations
    leak: LeakSettings
    dns_stub_port: int | None
    target: str | None = None  # config name of the active target, for status


@dataclass(frozen=True)
class RoutingPlan:
    """The whole desired state, applied atomically."""

    policies: tuple[PolicyPlan, ...] = ()
