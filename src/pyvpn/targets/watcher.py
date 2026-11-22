"""Target status reconciliation."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass

from pyvpn.config.models import Target
from pyvpn.state import IPAddress, TargetStatus
from pyvpn.targets.resolver import resolve_interfaces

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class InterfaceSnapshot:
    name: str
    ifindex: int
    up: bool
    addresses: tuple[IPAddress, ...] = ()
    gateways: tuple[IPAddress, ...] = ()  # main-table default next hops, IPv4 first


def status_for_target(
    target: Target,
    interfaces: Iterable[InterfaceSnapshot],
    *,
    probe_ok: bool = False,
) -> TargetStatus:
    """Build one target status from a point-in-time interface snapshot.

    ``probe_ok`` is the target's probe health (see ``pyvpn.targets.health``).
    It only matters for targets with ``probe: true``, which stay unusable
    unless it is true: fail closed.
    """

    snapshots = tuple(interfaces)
    matches = resolve_interfaces(target.interface, (item.name for item in snapshots))
    if not matches:
        return TargetStatus(
            name=target.name,
            interface=None,
            ifindex=None,
            usable=False,
        )

    snapshots_by_name = {item.name: item for item in snapshots}
    candidates = [snapshots_by_name[name] for name in matches if name in snapshots_by_name]
    snapshot = next((item for item in candidates if item.up and item.addresses), candidates[0])
    if target.gateway == "auto":
        gateways = snapshot.gateways
    elif target.gateway is None:
        gateways = ()
    else:
        gateways = (target.gateway,)

    usable = (
        snapshot.up
        and bool(snapshot.addresses)
        and (probe_ok or not target.probe)
        and (target.gateway != "auto" or bool(gateways))
    )
    # TargetStatus carries one next hop (Phase 0 contract); IPv4 is preferred.
    return TargetStatus(
        name=target.name,
        interface=snapshot.name,
        ifindex=snapshot.ifindex,
        usable=usable,
        gateway=gateways[0] if usable and gateways else None,
        addresses=snapshot.addresses,
    )


class SnapshotTargetWatcher:
    """Reconcile configured targets whenever a snapshot stream changes.

    Implements the ``pyvpn.services.TargetWatcher`` protocol on top of any
    OS-specific stream of interface snapshots (e.g. Linux netlink). It sends
    no probes, so targets with ``probe: true`` stay unusable here; use
    :class:`pyvpn.targets.health.ProbingTargetWatcher` for those.
    """

    def __init__(
        self,
        targets: Iterable[Target],
        events: AsyncIterator[Iterable[InterfaceSnapshot]],
    ) -> None:
        self._targets = tuple(targets)
        self._events = events

    async def statuses(self) -> AsyncIterator[dict[str, TargetStatus]]:
        # Snapshot bursts include changes that affect no target (e.g. routes
        # in pyvpn's own tables after an apply); emitting an identical map
        # would trigger another reconcile for nothing.
        last: dict[str, TargetStatus] | None = None
        async for snapshots in self._events:
            snapshot_tuple = tuple(snapshots)
            statuses = {
                target.name: status_for_target(target, snapshot_tuple) for target in self._targets
            }
            if statuses != last:
                last = statuses
                yield statuses
