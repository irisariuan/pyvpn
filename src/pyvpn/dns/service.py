"""Loopback DNS listeners implementing the Phase 0 DnsService protocol."""

from __future__ import annotations

import asyncio
import logging
import secrets
import struct
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterator
from contextlib import suppress
from copy import copy
from dataclasses import replace
from ipaddress import IPv4Network, IPv6Network
from time import monotonic
from typing import Protocol, cast, runtime_checkable

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdatatype
from dns.rdtypes.ANY.CNAME import CNAME
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.NS import NS
from dns.rdtypes.IN.SRV import SRV
from dns.rdtypes.svcbbase import IPv4HintParam, IPv6HintParam, ParamKey, SVCBBase
from dns.rrset import RRset

from pyvpn.dns.upstream import MAX_WIRE_SIZE, BoundUpstream
from pyvpn.services import DestCallback, RuleMatcher
from pyvpn.state import DestSet, PolicyPlan

log = logging.getLogger(__name__)
_CANARY = dns.name.from_text("use-application-dns.net.")
_RESOLVE_TIMEOUT = 5.0
_TCP_IDLE_TIMEOUT = 10.0
_MAX_UDP_QUERIES = 256
_MAX_TCP_CLIENTS = 256
_LISTEN_ADDRESS = "127.0.0.1"
_MAX_ALIAS_ORIGINS = 4096
_SERVICE_QUERY_TYPES = frozenset({dns.rdatatype.HTTPS, dns.rdatatype.SVCB, dns.rdatatype.ANY})
_ALIAS_QUERY_TYPES = _SERVICE_QUERY_TYPES | {dns.rdatatype.A, dns.rdatatype.AAAA}

Upstream = Callable[[PolicyPlan, dns.message.Message], Awaitable[dns.message.Message]]
ClientAddress = tuple[str, int]
DomainChain = tuple[str, ...]
AliasKey = tuple[int, int, dns.name.Name]
AliasTargets = dict[dns.name.Name, int]


@runtime_checkable
class _ChainMatcher(Protocol):
    def match_chain(self, *domains: str) -> int | None: ...


@runtime_checkable
class _ScopedMatcher(Protocol):
    def scoped(self, policy_id: int) -> RuleMatcher: ...


class PolicyDnsService:
    """Manage one UDP/TCP listener pair per plan with a DNS stub port."""

    def __init__(
        self,
        upstream: Upstream,
        *,
        matcher_factory: Callable[[], RuleMatcher] | None = None,
    ) -> None:
        """The composition root supplies a factory for the active config's matcher."""
        self._upstream = upstream
        self._stubs: dict[int, _Stub] = {}
        self._lock = asyncio.Lock()
        self._callback: DestCallback | None = None
        self._matcher_factory = matcher_factory
        # Clients may use a cached binding after a listener is replaced. Keep the
        # originating names by stub and recheck them against the committed matcher.
        self._alias_origins: dict[AliasKey, dict[DomainChain, float]] = {}
        self._alias_count = 0

    def on_answer(self, cb: DestCallback) -> None:
        self._callback = cb

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
                    await self._close_upstream(pid)
                return
            await self._stop(pid)
            stub = _Stub(self, plan)
            try:
                await stub.open(port)
            except BaseException:
                await self._close_upstream(pid)
                raise
            self._stubs[pid] = stub

    async def stop(self, policy_id: int) -> None:
        async with self._lock:
            await self._stop(policy_id)

    async def _stop(self, policy_id: int) -> None:
        stub = self._stubs.pop(policy_id, None)
        if stub is not None:
            try:
                await stub.close()
            finally:
                await self._close_upstream(policy_id)

    async def _close_upstream(self, policy_id: int) -> None:
        if isinstance(self._upstream, BoundUpstream):
            await self._upstream.close_policy(policy_id)

    def is_listening(self, policy_id: int) -> bool:
        return policy_id in self._stubs

    def _origins(self, key: AliasKey) -> set[DomainChain]:
        now = monotonic()
        return {
            origin for origin, expires in self._alias_origins.get(key, {}).items() if expires > now
        }

    def _remember_aliases(
        self, key: AliasKey, origins: set[DomainChain], targets: AliasTargets
    ) -> None:
        policy_id, rdclass, _ = key
        now = monotonic()
        entries = {(policy_id, rdclass, name): ttl for name, ttl in targets.items()}
        if self._alias_count + len(entries) * len(origins) > _MAX_ALIAS_ORIGINS:
            for alias, known in list(self._alias_origins.items()):
                live = {origin: expires for origin, expires in known.items() if expires > now}
                self._alias_count -= len(known) - len(live)
                if live:
                    self._alias_origins[alias] = live
                else:
                    del self._alias_origins[alias]
            available = _MAX_ALIAS_ORIGINS - self._alias_count
            for alias in entries:
                available -= len(origins.difference(self._alias_origins.get(alias, {})))
                if available < 0:
                    raise RuntimeError("DNS alias tracking capacity exceeded")

        for alias, ttl in entries.items():
            known = self._alias_origins.setdefault(alias, {})
            # A zero-TTL binding can still be followed within the same resolution.
            expires = now + (ttl or _RESOLVE_TIMEOUT)
            for origin in origins:
                if origin not in known:
                    self._alias_count += 1
                known[origin] = max(known.get(origin, 0), expires)

    async def _publish(
        self,
        plan: PolicyPlan,
        response: dns.message.Message,
        inherited: set[DomainChain],
    ) -> tuple[set[DomainChain], AliasTargets] | None:
        if (
            not isinstance(response, dns.message.QueryMessage)
            or response.rcode() != dns.rcode.NOERROR
        ):
            return None
        question = response.question[0]
        chain = response.resolve_chaining()
        dests, targets = _destinations(plan.policy_id, response, chain)
        # A client can follow a CNAME separately or refresh its shorter-lived address.
        if not inherited and question.rdtype not in _ALIAS_QUERY_TYPES:
            targets.clear()
        if not dests and not targets:
            return None
        if self._matcher_factory is None:
            if plan.dests is not None:
                raise RuntimeError("DNS destination matching is unavailable")
            return None
        matcher = self._matcher_factory()
        if isinstance(matcher, _ScopedMatcher):
            matcher = matcher.scoped(plan.policy_id)
        matches: dict[DomainChain, int] = {}
        for origin in inherited:
            if (winner := _match_chain(matcher, origin)) is not None:
                matches[origin] = winner
        if not matches:
            domains = _chain_domains(chain)
            winner = _match_chain(matcher, domains)
            if winner is None:
                return None
            matches[domains] = winner
            targets.pop(question.name, None)
        if dests:
            if self._callback is None:
                raise RuntimeError("DNS destination publication is unavailable")
            await self._callback(replace(dests, policy_id=min(matches.values())))
        return (set(matches), targets) if targets else None


class _Stub(asyncio.DatagramProtocol):
    def __init__(self, service: PolicyDnsService, plan: PolicyPlan) -> None:
        self.service = service
        self.plan = plan
        self._udp: asyncio.DatagramTransport | None = None
        self._tcp: asyncio.Server | None = None
        self._udp_tasks: set[asyncio.Task[None]] = set()
        self._tcp_tasks: set[asyncio.Task[None]] = set()
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
        await asyncio.gather(*self._udp_tasks, *self._tcp_tasks, return_exceptions=True)
        if self._tcp is not None:
            await self._tcp.wait_closed()

    def cancel_queries(self) -> None:
        self._generation += 1
        for task in self._udp_tasks | self._tcp_tasks:
            task.cancel()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._udp = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: ClientAddress) -> None:
        if len(self._udp_tasks) < _MAX_UDP_QUERIES:
            task = asyncio.create_task(self._reply_udp(data, addr))
            self._udp_tasks.add(task)
            task.add_done_callback(self._udp_tasks.discard)

    async def _reply_udp(self, data: bytes, addr: ClientAddress) -> None:
        reply = await self.answer(data, tcp=False)
        if reply is not None and self._udp is not None:
            self._udp.sendto(reply, addr)

    def _accept_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self._tcp_tasks) >= _MAX_TCP_CLIENTS:
            writer.close()
            return
        task = asyncio.create_task(self._reply_tcp(reader, writer))
        # A task cancelled before its first step never enters its try/finally.
        task.add_done_callback(lambda _: writer.close())
        self._tcp_tasks.add(task)
        task.add_done_callback(self._tcp_tasks.discard)

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
        question = query.question[0]
        key = (plan.policy_id, question.rdclass, question.name)
        follows_alias = question.rdtype in _ALIAS_QUERY_TYPES
        inherited = self.service._origins(key) if follows_alias else set()
        try:
            async with asyncio.timeout(_RESOLVE_TIMEOUT):
                response = await self._resolve(plan, query)
                if self._generation == generation:
                    if follows_alias:
                        inherited.update(self.service._origins(key))
                    aliases = await self.service._publish(plan, response, inherited)
                    if self._generation == generation:
                        response.id = query.id
                        wire = self._to_wire(response, query, tcp)
                        if aliases is not None:
                            self.service._remember_aliases(key, *aliases)
                        return wire
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


def _chain_domains(chain: dns.message.ChainingResult) -> DomainChain:
    names = [rrset.name for rrset in chain.cnames]
    names.append(chain.canonical_name)
    if chain.answer is not None and chain.answer.rdtype == dns.rdatatype.CNAME:
        names.extend(record.target for record in chain.answer if isinstance(record, CNAME))
    return tuple(name.canonicalize().to_text(omit_final_dot=True) for name in names)


def _match_chain(matcher: RuleMatcher, domains: DomainChain) -> int | None:
    if isinstance(matcher, _ChainMatcher):
        return matcher.match_chain(*domains)
    # Phase 0 matchers can compare individual names. Policy IDs follow config order.
    matches = (matcher.match(domain) for domain in domains)
    return min((policy_id for policy_id in matches if policy_id is not None), default=None)


def _service_bindings(
    answer: RRset,
    additional: dict[dns.name.Name, list[RRset]],
    related: set[dns.name.Name],
    targets: AliasTargets,
) -> Iterator[SVCBBase]:
    """Follow in-message AliasMode and CNAME records to ServiceMode bindings."""
    pending = [answer.name]
    visited: set[dns.name.Name] = set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        related.add(name)
        bindings: list[SVCBBase] = []
        ttl = 0
        rrsets = [answer] if name == answer.name else additional.get(name, [])
        for rrset in rrsets:
            if rrset.rdtype == answer.rdtype:
                bindings.extend(record for record in rrset if isinstance(record, SVCBBase))
                ttl = max(ttl, rrset.ttl)
            elif rrset.rdtype == dns.rdatatype.CNAME:
                pending.extend(record.target for record in rrset if isinstance(record, CNAME))

        aliases = [record.target for record in bindings if record.priority == 0]
        if aliases:
            # RFC 9460 §2.4.1 gives AliasMode precedence over ServiceMode.
            for target in aliases:
                if target != dns.name.root:
                    targets[target] = max(targets.get(target, 0), ttl)
                    pending.append(target)
        else:
            for record in bindings:
                target = name if record.target == dns.name.root else record.target
                targets[target] = max(targets.get(target, 0), ttl)
                related.add(target)
                yield record


def _destinations(
    policy_id: int, response: dns.message.QueryMessage, chain: dns.message.ChainingResult
) -> tuple[DestSet, AliasTargets]:
    """Collect the answer, service hints, and addresses for referenced names."""
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
    related = {chain.canonical_name}
    targets: AliasTargets = {}
    for rrset in chain.cnames:
        for record in rrset:
            if isinstance(record, CNAME):
                targets[record.target] = max(targets.get(record.target, 0), rrset.ttl)
    additional: dict[dns.name.Name, list[RRset]] = defaultdict(list)
    for rrset in response.additional:
        if rrset.rdclass == question.rdclass:
            additional[rrset.name].append(rrset)

    for rrset in answers:
        if rrset.rdtype == dns.rdatatype.A:
            v4.update(IPv4Network(str(record)) for record in rrset)
        elif rrset.rdtype == dns.rdatatype.AAAA:
            v6.update(IPv6Network(str(record)) for record in rrset)
        elif rrset.rdtype in (dns.rdatatype.HTTPS, dns.rdatatype.SVCB):
            for record in _service_bindings(rrset, additional, related, targets):
                hint4 = record.params.get(ParamKey.IPV4HINT)
                hint6 = record.params.get(ParamKey.IPV6HINT)
                if isinstance(hint4, IPv4HintParam):
                    v4.update(IPv4Network(address) for address in hint4.addresses)
                if isinstance(hint6, IPv6HintParam):
                    v6.update(IPv6Network(address) for address in hint6.addresses)
        else:
            for record in rrset:
                if isinstance(record, (CNAME, NS, SRV)):
                    related.add(record.target)
                    if isinstance(record, CNAME):
                        targets[record.target] = max(targets.get(record.target, 0), rrset.ttl)
                elif isinstance(record, MX):
                    related.add(record.exchange)

    pending = list(related)
    while pending:
        for rrset in additional.get(pending.pop(), []):
            if rrset.rdtype == dns.rdatatype.A:
                v4.update(IPv4Network(str(record)) for record in rrset)
            elif rrset.rdtype == dns.rdatatype.AAAA:
                v6.update(IPv6Network(str(record)) for record in rrset)
            elif rrset.rdtype == dns.rdatatype.CNAME:
                for record in rrset:
                    if isinstance(record, CNAME):
                        targets[record.target] = max(targets.get(record.target, 0), rrset.ttl)
                        if record.target not in related:
                            related.add(record.target)
                            pending.append(record.target)
    return DestSet(policy_id, frozenset(v4), frozenset(v6)), targets
