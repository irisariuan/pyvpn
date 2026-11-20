"""Send DNS only over sockets bound to a policy's target interface."""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import struct
from ipaddress import IPv6Address, ip_address
from typing import Literal

import aiohttp
import dns.flags
import dns.message

from pyvpn.state import IPAddress, PolicyPlan

DnsProtocol = Literal["plain", "dot", "doh"]
MAX_WIRE_SIZE = 65535
_DNS_MEDIA_TYPE = "application/dns-message"


def upstream_endpoint(server: str | None, protocol: DnsProtocol) -> tuple[IPAddress, str]:
    if not server:
        raise ValueError("a numeric DNS upstream address is required")
    name, at, address_text = server.partition("@")
    if not at:
        address_text = name
    if "%" in address_text:
        raise ValueError("use an unscoped address; the policy supplies the interface")
    address = ip_address(address_text)
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("the DNS upstream must be a remote unicast address")
    if not at:
        return address, str(address)
    if (
        protocol == "plain"
        or not name
        or not name.isascii()
        or any(not (character.isalnum() or character in ".-") for character in name)
    ):
        raise ValueError("an optional TLS name must be a DNS hostname followed by @address")
    return address, name


def _bound_socket(
    interface: str, family: socket.AddressFamily, kind: socket.SocketKind, proto: int = 0
) -> socket.socket:
    option = getattr(socket, "SO_BINDTODEVICE", None)
    if option is None:
        raise OSError("interface-bound DNS sockets require SO_BINDTODEVICE")
    if not interface or "\0" in interface:
        raise ValueError("invalid interface for DNS upstream")
    sock = socket.socket(family, kind, proto)
    try:
        sock.setsockopt(socket.SOL_SOCKET, option, os.fsencode(interface) + b"\0")
        sock.setblocking(False)
    except BaseException:
        sock.close()
        raise
    return sock


class BoundUpstream:
    """Wire-format transports; callers enforce a single deadline for the exchange."""

    def __init__(self, tls_context: ssl.SSLContext | None = None) -> None:
        self._tls = tls_context if tls_context is not None else ssl.create_default_context()
        if not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("DNS over TLS and HTTPS require certificate and hostname verification")

    async def __call__(self, plan: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        interface = plan.interface
        if plan.route != "dev" or not interface:
            raise ValueError("DNS upstream requires an active target interface")
        protocol = plan.leak.dns_protocol
        address, name = upstream_endpoint(plan.leak.dns_server, protocol)
        wire = query.to_wire()

        if protocol == "doh":
            response = await self._https(interface, address, name, wire)
        elif protocol == "dot":
            response = await self._stream(interface, address, 853, wire, tls_name=name)
        else:
            response = await self._udp(interface, address, wire)
            header = dns.message.from_wire(response, raise_on_truncation=False, question_only=True)
            if header.flags & dns.flags.TC:
                if not query.is_response(header):
                    raise ValueError("truncated DNS response does not match the query")
                response = await self._stream(interface, address, 53, wire)
        return dns.message.from_wire(response)

    async def _udp(self, interface: str, address: IPAddress, wire: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        with _bound_socket(interface, _family(address), socket.SOCK_DGRAM) as sock:
            await loop.sock_connect(sock, (str(address), 53))
            await loop.sock_sendall(sock, wire)
            return await loop.sock_recv(sock, MAX_WIRE_SIZE)

    async def _stream(
        self,
        interface: str,
        address: IPAddress,
        port: int,
        wire: bytes,
        *,
        tls_name: str | None = None,
    ) -> bytes:
        sock = _bound_socket(interface, _family(address), socket.SOCK_STREAM)
        try:
            await asyncio.get_running_loop().sock_connect(sock, (str(address), port))
            reader, writer = await asyncio.open_connection(
                sock=sock,
                ssl=self._tls if tls_name else None,
                server_hostname=tls_name,
            )
        except BaseException:
            sock.close()
            raise
        try:
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            return await reader.readexactly(int.from_bytes(await reader.readexactly(2), "big"))
        finally:
            writer.close()

    async def _https(self, interface: str, address: IPAddress, name: str, wire: bytes) -> bytes:
        def make_socket(info: tuple[int, int, int, str, object]) -> socket.socket:
            family, kind, proto, _, _ = info
            return _bound_socket(
                interface, socket.AddressFamily(family), socket.SocketKind(kind), proto
            )

        authority = f"[{address}]" if address.version == 6 else str(address)
        headers = {"Accept": _DNS_MEDIA_TYPE, "Content-Type": _DNS_MEDIA_TYPE}
        if name != str(address):
            headers["Host"] = name
        connector = aiohttp.TCPConnector(ssl=self._tls, socket_factory=make_socket)
        async with (
            aiohttp.ClientSession(
                connector=connector,
                trust_env=False,
                auto_decompress=False,
            ) as client,
            client.post(
                f"https://{authority}/dns-query",
                data=wire,
                headers=headers,
                server_hostname=name,
                allow_redirects=False,
            ) as response,
        ):
            if response.status != 200 or response.content_type != _DNS_MEDIA_TYPE:
                raise ValueError("invalid DoH status or content type")
            body = bytearray()
            async for chunk in response.content.iter_chunked(4096):
                body.extend(chunk)
                if len(body) > MAX_WIRE_SIZE:
                    raise ValueError("DoH response exceeds the DNS wire size limit")
            return bytes(body)


def _family(address: IPAddress) -> socket.AddressFamily:
    return socket.AF_INET if address.version == 4 else socket.AF_INET6
