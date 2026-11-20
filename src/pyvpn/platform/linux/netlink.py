"""Linux netlink interface, address, route, and event helpers."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable
from ipaddress import ip_address
from typing import Any

from pyvpn.config.models import Target
from pyvpn.state import IPAddress, TargetStatus
from pyvpn.targets.watcher import InterfaceSnapshot


def _text(message: dict[str, Any], key: str) -> str | None:
    value = message.get(key)
    return str(value) if value is not None else None


def parse_address(message: dict[str, Any]) -> IPAddress | None:
    """Extract a local IPv4/IPv6 address from a pyroute2 netlink message."""

    value = _text(message, "address")
    if value is None:
        attrs = message.get("attrs", ())
        for attr_name, attr_value in attrs:
            if attr_name in ("IFA_ADDRESS", "IFA_LOCAL"):
                value = str(attr_value)
                break
    if value is None:
        return None
    try:
        return ip_address(value)
    except ValueError:
        return None


def parse_gateway(message: dict[str, Any]) -> IPAddress | None:
    """Extract a gateway from a route netlink message."""

    attrs = message.get("attrs", ())
    for attr_name, attr_value in attrs:
        if attr_name in ("RTA_GATEWAY", "gateway"):
            try:
                return ip_address(str(attr_value))
            except ValueError:
                return None
    return None


class NetlinkReader:
    """Read and watch interfaces using pyroute2 when available."""

    async def snapshots(self) -> tuple[InterfaceSnapshot, ...]:
        return await asyncio.to_thread(self._read_snapshots)

    def _read_snapshots(self) -> tuple[InterfaceSnapshot, ...]:
        try:
            from pyroute2 import IPRoute
        except ImportError as exc:
            raise RuntimeError("pyroute2 is required for live target discovery") from exc

        with IPRoute() as ipr:
            links = ipr.get_links()
            addresses = ipr.get_addr()
            routes = ipr.get_routes()

        by_index: dict[int, list[IPAddress]] = {}
        for message in addresses:
            index = int(message.get("index", 0))
            address = parse_address(message)
            if address is not None:
                by_index.setdefault(index, []).append(address)

        gateways: dict[int, IPAddress] = {}
        for message in routes:
            index = int(message.get("oif", 0))
            gateway = parse_gateway(message)
            if index and gateway is not None:
                gateways.setdefault(index, gateway)

        snapshots: list[InterfaceSnapshot] = []
        for message in links:
            index = int(message.get("index", 0))
            name: str | None = None
            for attr_name, attr_value in message.get("attrs", ()):
                if attr_name == "IFLA_IFNAME":
                    name = str(attr_value)
                    break
            if name is None:
                continue

            flags = int(message.get("flags", 0))
            up = bool(flags & 0x1)
            snapshots.append(
                InterfaceSnapshot(
                    name=name,
                    ifindex=index,
                    up=up,
                    addresses=tuple(by_index.get(index, [])),
                    gateway=gateways.get(index),
                )
            )
        return tuple(snapshots)

    async def events(self) -> AsyncIterator[tuple[InterfaceSnapshot, ...]]:
        """Yield snapshots after netlink changes."""

        try:
            from pyroute2 import IPRoute
        except ImportError as exc:
            raise RuntimeError("pyroute2 is required for live target discovery") from exc

        with IPRoute() as ipr:
            ipr.bind()
            while True:
                messages = await asyncio.to_thread(ipr.get)
                if messages:
                    yield await self.snapshots()


class NetlinkTargetWatcher:
    """TargetWatcher backed by live Linux netlink state."""

    def __init__(self, targets: Iterable[Target], reader: NetlinkReader | None = None) -> None:
        self._targets = tuple(targets)
        self._reader = reader or NetlinkReader()

    async def statuses(self) -> AsyncIterator[dict[str, TargetStatus]]:
        yield await self._statuses_for(await self._reader.snapshots())
        async for snapshots in self._reader.events():
            yield await self._statuses_for(snapshots)

    async def _statuses_for(
        self, snapshots: tuple[InterfaceSnapshot, ...]
    ) -> dict[str, TargetStatus]:
        from pyvpn.targets.watcher import status_for_target

        return {target.name: status_for_target(target, snapshots) for target in self._targets}
