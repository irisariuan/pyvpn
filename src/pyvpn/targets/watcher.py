"""Target status reconciliation."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass

from pyvpn.config.models import Target
from pyvpn.state import IPAddress, TargetStatus
from pyvpn.targets.resolver import resolve_interfaces


@dataclass(frozen=True)
class InterfaceSnapshot:
    name: str
    ifindex: int
    up: bool
    addresses: tuple[IPAddress, ...] = ()
    gateway: IPAddress | None = None


def status_for_target(
    target: Target,
    interfaces: Iterable[InterfaceSnapshot],
) -> TargetStatus:
    """Build one target status from a point-in-time interface snapshot."""

    if target.probe:
        raise NotImplementedError(
            f"target {target.name!r} enables probing, which is not supported yet"
        )

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
    gateway = target.gateway
    if gateway == "auto":
        gateway = snapshot.gateway

    usable = snapshot.up and bool(snapshot.addresses)
    return TargetStatus(
        name=target.name,
        interface=snapshot.name,
        ifindex=snapshot.ifindex,
        usable=usable,
        gateway=gateway if usable else None,
        addresses=snapshot.addresses,
    )


class TargetWatcher:
    """Reconcile configured targets whenever an event stream changes."""

    def __init__(
        self,
        targets: Iterable[Target],
        events: AsyncIterator[Iterable[InterfaceSnapshot]],
    ) -> None:
        self._targets = tuple(targets)
        self._events = events

    async def statuses(self) -> AsyncIterator[dict[str, TargetStatus]]:
        async for snapshots in self._events:
            snapshot_tuple = tuple(snapshots)
            yield {
                target.name: status_for_target(target, snapshot_tuple) for target in self._targets
            }
