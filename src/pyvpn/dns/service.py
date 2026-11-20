"""Loopback DNS listeners implementing the Phase 0 DnsService protocol."""

from __future__ import annotations

import asyncio
import logging
import secrets
import struct
from collections.abc import Awaitable, Callable
from contextlib import suppress
from copy import copy
from ipaddress import IPv4Network, IPv6Network
from typing import cast

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdatatype
from dns.rdtypes.svcbbase import IPv4HintParam, IPv6HintParam, ParamKey, SVCBBase

from pyvpn.dns.upstream import MAX_WIRE_SIZE, BoundUpstream
from pyvpn.services import DestCallback, RuleMatcher
from pyvpn.state import DestSet, PolicyPlan

log = logging.getLogger(__name__)
_CANARY = dns.name.from_text("use-application-dns.net.")
_RESOLVE_TIMEOUT = 5.0
_TCP_IDLE_TIMEOUT = 10.0
_MAX_CLIENT_TASKS = 256
_LISTEN_ADDRESS = "127.0.0.1"

Upstream = Callable[[PolicyPlan, dns.message.Message], Awaitable[dns.message.Message]]
ClientAddress = tuple[str, int]


class PolicyDnsService:
    """Manage one UDP/TCP listener pair per plan with a DNS stub port."""

    def __init__(self, upstream: Upstream | None = None) -> None:
        self._upstream = upstream if upstream is not None else BoundUpstream()
        self._stubs: dict[int, _Stub] = {}
        self._lock = asyncio.Lock()
        self._callback: DestCallback | None = None
        self._matcher: RuleMatcher | None = None

    def on_answer(self, cb: DestCallback) -> None:
        self._callback = cb

    def set_matcher(self, matcher: RuleMatcher) -> None:
        """Supply the current rule matcher, including after config reload."""
        self._matcher = matcher
        for stub in self._stubs.values():
            stub.cancel_queries()

    async def start(self, plan: PolicyPlan) -> None:
        async with self._lock:
            pid, port = plan.policy_id, plan.dns_stub_port
            if port is None or not plan.leak.dns_via_target:
                await self._stop(pid)
                return
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid DNS stub port {port}")
            stub = self._stubs.get(pid)
            if stub is not None and stub.plan.dns_stub_port == port:
                if stub.plan != plan:
                    stub.plan = plan
                    stub.cancel_queries()
                return
            await self._stop(pid)
            stub = _Stub(self, plan)
            await stub.open(port)
            self._stubs[pid] = stub

    async def stop(self, policy_id: int) -> None:
        async with self._lock:
            await self._stop(policy_id)

    async def _stop(self, policy_id: int) -> None:
        stub = self._stubs.pop(policy_id, None)
        if stub is not None:
            await stub.close()

    def is_listening(self, policy_id: int) -> bool:
        return policy_id in self._stubs

    async def _publish(self, plan: PolicyPlan, response: dns.message.Message) -> None:
        if plan.dests is None or not isinstance(response, dns.message.QueryMessage):
            return
        if response.rcode() != dns.rcode.NOERROR:
            return
        dests = _destinations(plan.policy_id, response)
        if not dests:
            return
        if self._matcher is None:
            raise RuntimeError("DNS destination matching is unavailable")
        domain = response.question[0].name.canonicalize().to_text(omit_final_dot=True)
        if self._matcher.match(domain) != plan.policy_id:
            return
        if self._callback is None:
            raise RuntimeError("DNS destination publication is unavailable")
        await self._callback(dests)


class _Stub(asyncio.DatagramProtocol):
    def __init__(self, service: PolicyDnsService, plan: PolicyPlan) -> None:
        self.service = service
        self.plan = plan
        self._udp: asyncio.DatagramTransport | None = None
        self._tcp: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._generation = 0
        self._closed = False

    async def open(self, port: int) -> None:
        loop = asyncio.get_running_loop()
        try:
            await loop.create_datagram_endpoint(lambda: self, local_addr=(_LISTEN_ADDRESS, port))
            self._tcp = await asyncio.start_server(self._accept_tcp, _LISTEN_ADDRESS, port)
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        self._closed = True
        if self._udp is not None:
            self._udp.close()
            self._udp = None
        if self._tcp is not None:
            self._tcp.close()
        self.cancel_queries()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._tcp is not None:
            await self._tcp.wait_closed()

    def cancel_queries(self) -> None:
        self._generation += 1
        for task in self._tasks:
            task.cancel()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._udp = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: ClientAddress) -> None:
        if len(self._tasks) < _MAX_CLIENT_TASKS:
            self._track(asyncio.create_task(self._reply_udp(data, addr)))

    def _track(self, task: asyncio.Task[None]) -> None:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _reply_udp(self, data: bytes, addr: ClientAddress) -> None:
        reply = await self.answer(data, tcp=False)
        if reply is not None and self._udp is not None:
            self._udp.sendto(reply, addr)

    def _accept_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self._tasks) >= _MAX_CLIENT_TASKS:
            writer.close()
            return
        task = asyncio.create_task(self._reply_tcp(reader, writer))
        # A task cancelled before its first step never enters its try/finally.
        task.add_done_callback(lambda _: writer.close())
        self._track(task)

    async def _reply_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with suppress(TimeoutError, OSError, asyncio.IncompleteReadError):
            while True:
                async with asyncio.timeout(_TCP_IDLE_TIMEOUT):
                    size = int.from_bytes(await reader.readexactly(2), "big")
                    data = await reader.readexactly(size)
                reply = await self.answer(data, tcp=True)
                if reply is None:
                    return
                writer.write(struct.pack("!H", len(reply)) + reply)
                async with asyncio.timeout(_TCP_IDLE_TIMEOUT):
                    await writer.drain()

    async def answer(self, data: bytes, *, tcp: bool) -> bytes | None:
        try:
            query = dns.message.from_wire(data)
        except dns.exception.DNSException:
            return None
        if query.flags & dns.flags.QR or len(query.question) != 1:
            return None
        plan = self.plan
        generation = self._generation
        try:
            async with asyncio.timeout(_RESOLVE_TIMEOUT):
                response = await self._resolve(plan, query)
                if self._generation == generation:
                    await self.service._publish(plan, response)
                    if self._generation == generation:
                        response.id = query.id
                        return self._to_wire(response, query, tcp)
        except asyncio.CancelledError:
            if self._closed or self._generation == generation:
                raise
        except Exception as error:
            log.debug("DNS resolution failed for policy %d (%s)", plan.policy_id, type(error))
        return self._to_wire(_error(query, dns.rcode.SERVFAIL), query, tcp)

    async def _resolve(self, plan: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        if query.opcode() != dns.opcode.QUERY:
            return _error(query, dns.rcode.NOTIMP)
        if plan.leak.block_doh and query.question[0].name == _CANARY:
            return _error(query, dns.rcode.NXDOMAIN)
        if plan.route != "dev" or not plan.interface:
            return _error(query, dns.rcode.SERVFAIL)
        outgoing = copy(query)
        outgoing.id = 0 if plan.leak.dns_protocol == "doh" else secrets.randbits(16)
        response = await self.service._upstream(plan, outgoing)
        if not outgoing.is_response(response) or response.flags & dns.flags.TC:
            return _error(query, dns.rcode.SERVFAIL)
        return response

    @staticmethod
    def _to_wire(response: dns.message.Message, query: dns.message.Message, tcp: bool) -> bytes:
        max_size = MAX_WIRE_SIZE if tcp else max(512, min(query.payload, 4096))
        return response.to_wire(max_size=max_size, prefer_truncation=True)


def _error(query: dns.message.Message, code: dns.rcode.Rcode) -> dns.message.Message:
    response = dns.message.make_response(query, recursion_available=True)
    response.set_rcode(code)
    return response


def _destinations(policy_id: int, response: dns.message.QueryMessage) -> DestSet:
    """Extract addresses at the end of the queried name's CNAME chain."""
    chain = response.resolve_chaining()
    question = response.question[0]
    if question.rdtype == dns.rdatatype.ANY:
        answers = [
            rrset
            for rrset in response.answer
            if rrset.name == chain.canonical_name and rrset.rdclass == question.rdclass
        ]
    else:
        answers = [chain.answer] if chain.answer is not None else []
    v4: set[IPv4Network] = set()
    v6: set[IPv6Network] = set()
    for rrset in answers:
        if rrset.rdtype == dns.rdatatype.A:
            v4.update(IPv4Network(str(record)) for record in rrset)
        elif rrset.rdtype == dns.rdatatype.AAAA:
            v6.update(IPv6Network(str(record)) for record in rrset)
        else:
            for record in rrset:
                if isinstance(record, SVCBBase):
                    hint4 = record.params.get(ParamKey.IPV4HINT)
                    hint6 = record.params.get(ParamKey.IPV6HINT)
                    if isinstance(hint4, IPv4HintParam):
                        v4.update(IPv4Network(address) for address in hint4.addresses)
                    if isinstance(hint6, IPv6HintParam):
                        v6.update(IPv6Network(address) for address in hint6.addresses)
    return DestSet(policy_id, frozenset(v4), frozenset(v6))
