"""Target status reconciliation."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass

from pyvpn.config.models import Target
from pyvpn.state import IPAddress, TargetStatus
from pyvpn.targets.resolver import resolve_interfaces

log = logging.getLogger(__name__)
_warned_probe: set[str] = set()


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
) -> TargetStatus:
    """Build one target status from a point-in-time interface snapshot."""

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

    if target.probe and target.name not in _warned_probe:
        _warned_probe.add(target.name)
        log.warning(
            "target %r sets probe: true, which is not supported yet; it stays unusable",
            target.name,
        )
    usable = (
        snapshot.up
        and bool(snapshot.addresses)
        and not target.probe
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
    OS-specific stream of interface snapshots (e.g. Linux netlink).
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
