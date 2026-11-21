"""Optional TCP reachability probes through target interfaces.

This module is OS-agnostic: it parses probe endpoints and runs probes, but
binding a socket to an interface is platform-specific (``SO_BINDTODEVICE`` on
Linux, ``IP_BOUND_IF`` on macOS, see PLAN.md §2.1). The caller passes a
:data:`Connector` from ``pyvpn.platform.<os>``; on Linux that is
:func:`pyvpn.platform.linux.netlink.tcp_connect_bound`.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable, Sequence

Connector = Callable[[str, str, int, float], bool]
"""``connect(interface, host, port, timeout)``: whether a TCP connect bound to
``interface`` succeeds. ``host`` is always an IP literal. Blocking; it is run
in a worker thread."""


def parse_probe(endpoint: str) -> tuple[str, int]:
    """Parse a probe endpoint in ``host:port`` form.

    Only IP literals are accepted: resolving a hostname would go through the
    system resolver, i.e. over the default route, outside the target.
    """

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


async def probe_target(
    interface: str,
    endpoints: Sequence[str],
    connect: Connector,
    timeout: float = 3.0,
) -> bool:
    """Return whether any endpoint is reachable through ``interface``.

    Runs the blocking ``connect`` in a worker thread so the event loop is not
    blocked.
    """

    for endpoint in endpoints:
        host, port = parse_probe(endpoint)
        if await asyncio.to_thread(connect, interface, host, port, timeout):
            return True
    return False
