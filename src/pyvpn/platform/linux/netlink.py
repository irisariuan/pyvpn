"""Linux netlink interface, address, route, and event helpers."""

from __future__ import annotations

import asyncio
import contextlib
import select
import threading
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from ipaddress import ip_address
from typing import Any, Protocol

from pyvpn.config.models import Target
from pyvpn.state import IPAddress, TargetStatus
from pyvpn.targets.watcher import InterfaceSnapshot, status_for_target

_RT_TABLE_MAIN = 254
_IFF_UP = 0x1
_IFF_RUNNING = 0x40
_IFF_LOWER_UP = 0x10000
_RT_SCOPE_LINK = 253  # link (fe80::/10, 169.254/16) and host (loopback) scopes
_IFA_F_DADFAILED = 0x08
_IFA_F_TENTATIVE = 0x40


class NetlinkEventSource(Protocol):
    def events(self) -> AsyncIterator[tuple[InterfaceSnapshot, ...]]: ...


def _attribute(message: Mapping[str, Any], name: str) -> Any:
    for key, value in message.get("attrs", ()):
        if key == name:
            return value
    return None


def address_is_routable(message: Mapping[str, Any]) -> bool:
    """Only global-scope, DAD-complete addresses can carry routed traffic.

    A link-local IPv6 address appears as soon as a link has carrier (before
    DHCP / RA), and a tentative or DAD-failed address cannot be used yet, so
    neither may make a target usable.
    """
    try:
        scope = int(message.get("scope", 0))
        flags = int(message.get("flags", 0))
        extra = _attribute(message, "IFA_FLAGS")
        if extra is not None:
            flags |= int(extra)
    except (TypeError, ValueError):
        return False
    return scope < _RT_SCOPE_LINK and not flags & (_IFA_F_TENTATIVE | _IFA_F_DADFAILED)


def parse_address(message: Mapping[str, Any]) -> IPAddress | None:
    """Extract the local IPv4/IPv6 address, preferring IFA_LOCAL over peer."""

    value = _attribute(message, "IFA_LOCAL")
    if value is None:
        value = _attribute(message, "IFA_ADDRESS")
    if value is None:
        value = message.get("address")
    if value is None:
        return None
    try:
        return ip_address(str(value))
    except ValueError:
        return None


def parse_gateway(message: Mapping[str, Any]) -> IPAddress | None:
    """Extract a gateway from a route netlink message."""

    value = _attribute(message, "RTA_GATEWAY")
    if value is None:
        value = message.get("gateway")
    if value is None:
        return None
    try:
        return ip_address(str(value))
    except ValueError:
        return None


def _default_gateways(
    routes: Iterable[Mapping[str, Any]],
) -> dict[int, dict[int, IPAddress]]:
    """Select the lowest-metric main-table default gateway per interface/family."""

    best: dict[tuple[int, int], tuple[int, IPAddress]] = {}
    for route in routes:
        try:
            if int(route.get("dst_len", -1)) != 0:
                continue
            table_value = _attribute(route, "RTA_TABLE")
            if table_value is None:
                table_value = route.get("table")
            if int(table_value) != _RT_TABLE_MAIN:
                continue
            oif_value = _attribute(route, "RTA_OIF")
            if oif_value is None:
                oif_value = route.get("oif")
            if oif_value is None:
                continue
            ifindex = int(oif_value)
            priority_value = _attribute(route, "RTA_PRIORITY")
            if priority_value is None:
                priority_value = route.get("priority", 0)
            priority = int(priority_value)
        except (TypeError, ValueError):
            continue

        gateway = parse_gateway(route)
        if gateway is None:
            continue

        key = (ifindex, gateway.version)
        current = best.get(key)
        if current is None or (priority, int(gateway)) < (current[0], int(current[1])):
            best[key] = (priority, gateway)

    gateways: dict[int, dict[int, IPAddress]] = {}
    for (ifindex, version), selected_route in best.items():
        gateway = selected_route[1]
        gateways.setdefault(ifindex, {})[version] = gateway
    return gateways


def _operstate(message: Mapping[str, Any]) -> str | None:
    value = _attribute(message, "IFLA_OPERSTATE")
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    if isinstance(value, int):
        return {0: "UNKNOWN", 6: "UP"}.get(value)
    return str(value).upper() if value is not None else None


def link_is_up(message: Mapping[str, Any]) -> bool:
    """Require administrative up plus carrier/operstate usability."""

    flags = int(message.get("flags", 0))
    if not flags & _IFF_UP:
        return False
    if flags & (_IFF_LOWER_UP | _IFF_RUNNING):
        return True
    return _operstate(message) in {"UP", "UNKNOWN"}


def _snapshots_from_messages(
    links: Iterable[Mapping[str, Any]],
    addresses: Iterable[Mapping[str, Any]],
    routes: Iterable[Mapping[str, Any]],
) -> tuple[InterfaceSnapshot, ...]:
    addresses_by_index: dict[int, list[IPAddress]] = {}
    for message in addresses:
        try:
            ifindex = int(message.get("index", 0))
        except (TypeError, ValueError):
            continue
        if not address_is_routable(message):
            continue
        address = parse_address(message)
        if address is not None:
            addresses_by_index.setdefault(ifindex, []).append(address)

    gateways_by_index = _default_gateways(routes)
    snapshots: list[InterfaceSnapshot] = []
    for message in links:
        try:
            ifindex = int(message.get("index", 0))
        except (TypeError, ValueError):
            continue
        name = _attribute(message, "IFLA_IFNAME")
        if name is None:
            continue

        interface_addresses = tuple(addresses_by_index.get(ifindex, ()))
        gateways = gateways_by_index.get(ifindex, {})
        address_families = {address.version for address in interface_addresses}
        snapshots.append(
            InterfaceSnapshot(
                name=str(name),
                ifindex=ifindex,
                up=link_is_up(message),
                addresses=interface_addresses,
                gateways=tuple(
                    gateways[version]
                    for version in (4, 6)
                    if version in address_families and version in gateways
                ),
            )
        )
    return tuple(snapshots)


class NetlinkReader:
    """Read and watch interfaces using pyroute2 when available."""

    async def snapshots(self) -> tuple[InterfaceSnapshot, ...]:
        return await asyncio.to_thread(self._read_snapshots)

    def _read_snapshots(self, ipr: Any | None = None) -> tuple[InterfaceSnapshot, ...]:
        try:
            from pyroute2 import IPRoute
        except ImportError as exc:
            raise RuntimeError("pyroute2 is required for live target discovery") from exc

        if ipr is not None:
            return _snapshots_from_messages(
                ipr.get_links(),
                ipr.get_addr(),
                ipr.get_routes(),
            )

        with IPRoute() as snapshot_ipr:
            return _snapshots_from_messages(
                snapshot_ipr.get_links(),
                snapshot_ipr.get_addr(),
                snapshot_ipr.get_routes(),
            )

    async def events(self) -> AsyncIterator[tuple[InterfaceSnapshot, ...]]:
        """Yield one refreshed snapshot per coalesced netlink event burst."""

        try:
            from pyroute2 import IPRoute
            from pyroute2.netlink.rtnl import (
                RTMGRP_IPV4_IFADDR,
                RTMGRP_IPV4_ROUTE,
                RTMGRP_IPV6_IFADDR,
                RTMGRP_IPV6_ROUTE,
                RTMGRP_LINK,
            )
        except ImportError as exc:
            raise RuntimeError("pyroute2 is required for live target discovery") from exc

        groups = (
            RTMGRP_LINK
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV6_IFADDR
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_ROUTE
        )
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[tuple[InterfaceSnapshot, ...]] = asyncio.Queue()
        stopping = threading.Event()

        def publish(snapshots: tuple[InterfaceSnapshot, ...]) -> None:
            loop.call_soon_threadsafe(queue.put_nowait, snapshots)

        worker = asyncio.create_task(
            asyncio.to_thread(self._watch, IPRoute, groups, stopping, publish)
        )
        pending: asyncio.Task[tuple[InterfaceSnapshot, ...]] | None = None
        try:
            while True:
                pending = asyncio.create_task(queue.get())
                done, _ = await asyncio.wait(
                    (pending, worker),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if worker in done:
                    if not pending.done():
                        pending.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await pending
                    pending = None
                    await worker
                    raise RuntimeError("netlink reader stopped without an error")
                snapshots = pending.result()
                pending = None
                yield snapshots
        finally:
            stopping.set()
            if pending is not None:
                pending.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await pending
            await asyncio.shield(worker)

    def _watch(
        self,
        iproute_type: Any,
        groups: int,
        stopping: threading.Event,
        publish: Callable[[tuple[InterfaceSnapshot, ...]], None],
    ) -> None:
        # Two sockets: dumps must not run on the multicast-bound socket, or
        # pyroute2 buffers events that arrive mid-dump internally, the fd never
        # becomes readable for them, and a change during a dump is lost. The
        # event socket is bound before the first dump, so any change after the
        # dump starts is seen on it and triggers another dump.
        with iproute_type() as events, iproute_type() as dumps:
            events.bind(groups=groups)
            fd = events.socket.fileno()
            publish(self._read_snapshots(dumps))
            while not stopping.is_set():
                if not select.select([fd], [], [], 0.1)[0]:
                    continue
                received = False
                while select.select([fd], [], [], 0)[0]:
                    messages = events.get()
                    received = received or bool(messages)
                if received:
                    publish(self._read_snapshots(dumps))


class NetlinkTargetWatcher:
    """TargetWatcher backed by live Linux netlink state."""

    def __init__(self, targets: Iterable[Target], reader: NetlinkEventSource | None = None) -> None:
        self._targets = tuple(targets)
        self._reader = reader or NetlinkReader()

    async def statuses(self) -> AsyncIterator[dict[str, TargetStatus]]:
        # Netlink bursts include changes that do not affect any target (e.g.
        # routes in pyvpn's own tables after an apply); emitting an identical
        # map would trigger another reconcile for nothing.
        last: dict[str, TargetStatus] | None = None
        async for snapshots in self._reader.events():
            statuses = self._statuses_for(snapshots)
            if statuses != last:
                last = statuses
                yield statuses

    def _statuses_for(self, snapshots: tuple[InterfaceSnapshot, ...]) -> dict[str, TargetStatus]:
        return {target.name: status_for_target(target, snapshots) for target in self._targets}
