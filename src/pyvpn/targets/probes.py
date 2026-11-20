"""Optional TCP reachability probes bound to target interfaces."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Sequence

# Linux-only socket option (value 25 on Linux); the constant is missing from
# the ``socket`` module elsewhere, where binding to a device is unsupported.
_SO_BINDTODEVICE: int = getattr(socket, "SO_BINDTODEVICE", 25)


def parse_probe(endpoint: str) -> tuple[str, int]:
    """Parse a probe endpoint in ``host:port`` form."""

    host, separator, port_text = endpoint.rpartition(":")
    if not separator or not host or not port_text:
        raise ValueError(f"invalid probe endpoint: {endpoint!r}")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError as exc:
        raise ValueError("probe targets must use IP literals") from exc
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid probe port: {port}")
    return str(address), port


def tcp_probe(interface: str, host: str, port: int, timeout: float = 3.0) -> bool:
    """Return whether a TCP connection succeeds while bound to interface."""

    ipaddress.ip_address(host)
    try:
        addresses = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
            flags=socket.AI_NUMERICHOST,
        )
    except socket.gaierror:
        return False

    for family, sock_type, proto, _, address in addresses:
        sock = socket.socket(family, sock_type, proto)
        try:
            sock.settimeout(timeout)
            try:
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    _SO_BINDTODEVICE,
                    interface.encode(),
                )
            except OSError:
                sock.close()
                continue
            sock.connect(address)
            return True
        except OSError:
            pass
        finally:
            sock.close()
    return False


async def probe_target(
    interface: str,
    endpoints: Sequence[str],
    timeout: float = 3.0,
) -> bool:
    """Run one or more configured TCP probes without blocking the event loop."""

    for endpoint in endpoints:
        host, port = parse_probe(endpoint)
        if await asyncio.to_thread(tcp_probe, interface, host, port, timeout):
            return True
    return False
