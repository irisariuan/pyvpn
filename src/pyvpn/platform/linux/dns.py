"""Linux socket factory for policy DNS upstreams."""

import os
import socket


def bound_dns_socket(
    interface: str, mark: int, family: socket.AddressFamily, kind: socket.SocketKind, proto: int = 0
) -> socket.socket:
    """Return a nonblocking socket pinned to the interface and policy table."""
    bind_option = getattr(socket, "SO_BINDTODEVICE", None)
    mark_option = getattr(socket, "SO_MARK", None)
    if bind_option is None or mark_option is None:
        raise OSError("policy DNS sockets require SO_BINDTODEVICE and SO_MARK")
    if not interface or "\0" in interface:
        raise ValueError("invalid interface for DNS upstream")
    sock = socket.socket(family, kind, proto)
    try:
        sock.setsockopt(socket.SOL_SOCKET, bind_option, os.fsencode(interface) + b"\0")
        sock.setsockopt(socket.SOL_SOCKET, mark_option, mark)
        sock.setblocking(False)
    except BaseException:
        sock.close()
        raise
    return sock
