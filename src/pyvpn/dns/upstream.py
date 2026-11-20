"""Send DNS only over sockets bound to a policy's target interface."""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import struct
from ipaddress import IPv6Address, ip_address
from typing import TYPE_CHECKING, Literal

import dns.flags
import dns.message

from pyvpn.state import IPAddress, PolicyPlan

if TYPE_CHECKING:
    import aiohttp

DnsProtocol = Literal["plain", "dot", "doh"]
MAX_WIRE_SIZE = 65535
_DNS_MEDIA_TYPE = "application/dns-message"
_DEFAULT_ADDRESS = "9.9.9.9"
_DEFAULT_TLS_NAME = "dns.quad9.net"


def upstream_endpoint(server: str | None, protocol: DnsProtocol) -> tuple[IPAddress, str]:
    if server is None:
        server = (
            _DEFAULT_ADDRESS if protocol == "plain" else f"{_DEFAULT_TLS_NAME}@{_DEFAULT_ADDRESS}"
        )
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
    interface: str, mark: int, family: socket.AddressFamily, kind: socket.SocketKind, proto: int = 0
) -> socket.socket:
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


class BoundUpstream:
    """Wire-format transports; callers enforce a single deadline for the exchange."""

    def __init__(self, tls_context: ssl.SSLContext | None = None) -> None:
        self._tls = tls_context if tls_context is not None else ssl.create_default_context()
        if not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("DNS over TLS and HTTPS require certificate and hostname verification")
        self._sessions: dict[tuple[int, str, int, IPAddress, str], aiohttp.ClientSession] = {}

    async def close_policy(self, policy_id: int) -> None:
        keys = [key for key in self._sessions if key[0] == policy_id]
        sessions = [self._sessions.pop(key) for key in keys]
        for session in sessions:
            await session.close()

    async def __call__(self, plan: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        interface = plan.interface
        if plan.route != "dev" or not interface:
            raise ValueError("DNS upstream requires an active target interface")
        protocol = plan.leak.dns_protocol
        address, name = upstream_endpoint(plan.leak.dns_server, protocol)
        wire = query.to_wire()

        if protocol == "doh":
            client = self._https_session(plan.policy_id, interface, plan.mark, address, name)
            response = await self._https(client, address, name, wire)
        elif protocol == "dot":
            response = await self._stream(interface, plan.mark, address, 853, wire, tls_name=name)
        else:
            response = await self._udp(interface, plan.mark, address, wire)
            header = dns.message.from_wire(response, raise_on_truncation=False, question_only=True)
            if header.flags & dns.flags.TC:
                if not query.is_response(header):
                    raise ValueError("truncated DNS response does not match the query")
                response = await self._stream(interface, plan.mark, address, 53, wire)
        return dns.message.from_wire(response)

    async def _udp(self, interface: str, mark: int, address: IPAddress, wire: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        with _bound_socket(interface, mark, _family(address), socket.SOCK_DGRAM) as sock:
            await loop.sock_connect(sock, (str(address), 53))
            await loop.sock_sendall(sock, wire)
            return await loop.sock_recv(sock, MAX_WIRE_SIZE)

    async def _stream(
        self,
        interface: str,
        mark: int,
        address: IPAddress,
        port: int,
        wire: bytes,
        *,
        tls_name: str | None = None,
    ) -> bytes:
        sock = _bound_socket(interface, mark, _family(address), socket.SOCK_STREAM)
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

    def _https_session(
        self, policy_id: int, interface: str, mark: int, address: IPAddress, name: str
    ) -> aiohttp.ClientSession:
        try:
            import aiohttp
        except ModuleNotFoundError as error:
            if error.name != "aiohttp":
                raise
            raise RuntimeError("DNS over HTTPS requires the snakevpn[doh] extra") from error

        key = (policy_id, interface, mark, address, name)
        if key in self._sessions:
            return self._sessions[key]

        def make_socket(info: tuple[int, int, int, str, object]) -> socket.socket:
            family, kind, proto, _, _ = info
            return _bound_socket(
                interface, mark, socket.AddressFamily(family), socket.SocketKind(kind), proto
            )

        connector = aiohttp.TCPConnector(ssl=self._tls, socket_factory=make_socket)
        client = aiohttp.ClientSession(
            connector=connector,
            cookie_jar=aiohttp.DummyCookieJar(),
            trust_env=False,
            auto_decompress=False,
        )
        self._sessions[key] = client
        return client

    async def _https(
        self, client: aiohttp.ClientSession, address: IPAddress, name: str, wire: bytes
    ) -> bytes:
        authority = f"[{address}]" if address.version == 6 else str(address)
        headers = {"Accept": _DNS_MEDIA_TYPE, "Content-Type": _DNS_MEDIA_TYPE}
        if name != str(address):
            headers["Host"] = name
        async with client.post(
            f"https://{authority}/dns-query",
            data=wire,
            headers=headers,
            server_hostname=name,
            allow_redirects=False,
            proxy=None,
        ) as response:
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
