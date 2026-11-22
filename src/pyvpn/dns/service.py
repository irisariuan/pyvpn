"""Loopback DNS listeners implementing the Phase 0 DnsService protocol."""

from __future__ import annotations

import asyncio
import errno
import logging
import secrets
import struct
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from contextlib import suppress
from copy import copy
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
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

from pyvpn.constants import STATE_DIR
from pyvpn.dns.aliases import AliasKey, AliasRows, AliasStore, DomainChain, Origins
from pyvpn.dns.upstream import MAX_WIRE_SIZE, BoundUpstream
from pyvpn.services import DestCallback, RuleMatcher
from pyvpn.state import DestSet, PolicyPlan

log = logging.getLogger(__name__)
_CANARY = dns.name.from_text("use-application-dns.net.")
_RESOLVE_TIMEOUT = 5.0
_TCP_IDLE_TIMEOUT = 10.0
_MAX_UDP_QUERIES = 256
_MAX_TCP_CLIENTS = 256
_UDP_RELEASE_TIMEOUT = 2.0
_LISTEN_ADDRESSES = ("127.0.0.1", "::1")
_IPV6_UNAVAILABLE = {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL}
_MAX_ALIAS_ORIGINS = 4096
_ALIAS_PATH = Path(STATE_DIR) / "dns-aliases.sqlite3"

Upstream = Callable[[PolicyPlan, dns.message.Message], Awaitable[dns.message.Message]]
ClientAddress = tuple[str, int] | tuple[str, int, int, int]


@runtime_checkable
class _ChainMatcher(Protocol):
    def match_chain(self, *domains: str) -> int | None: ...


@runtime_checkable
class _DecidingMatcher(Protocol):
    def decide_chain(self, *domains: str) -> tuple[int, bool] | None: ...


# (policy id, drop): which policy owns a name's addresses, and whether they
# go into its drop set (a ``drop:`` rule) rather than its route set.
_Owner = tuple[int, bool]


@runtime_checkable
class _ScopedMatcher(Protocol):
    def scoped(self, policy_id: int) -> RuleMatcher: ...


class PolicyDnsService:
    """Manage the loopback UDP and TCP listeners for each plan with a stub port."""

    def __init__(
        self,
        upstream: Upstream,
        *,
        alias_path: Path | None = None,
        matcher_factory: Callable[[], RuleMatcher] | None = None,
    ) -> None:
        """The composition root supplies a factory for the active config's matcher."""
        self._upstream = upstream
        self._stubs: dict[int, _Stub] = {}
        self._lock = asyncio.Lock()
        self._callback: DestCallback | None = None
        self._matcher_factory = matcher_factory
        self._aliases = AliasStore(
            alias_path if alias_path is not None else _ALIAS_PATH, time.monotonic
        )
        self._publication_lock = asyncio.Lock()

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

    async def _publish(
        self,
        plan: PolicyPlan,
        response: dns.message.Message,
        inherited: Origins,
        key: AliasKey,
    ) -> None:
        if not isinstance(response, dns.message.QueryMessage) or response.rcode() not in (
            dns.rcode.NOERROR,
            dns.rcode.NXDOMAIN,
        ):
            return
        chain = response.resolve_chaining()
        paths = _answer_paths(response, chain)
        if not paths.addresses and not paths.aliases:
            return
        if self._matcher_factory is None:
            if plan.dests is not None:
                raise RuntimeError("DNS destination matching is unavailable")
            return
        matcher = self._matcher_factory()
        if isinstance(matcher, _ScopedMatcher):
            matcher = matcher.scoped(plan.policy_id)
        prefixes = inherited or {(): float("inf")}
        owners: dict[IPv4Network | IPv6Network, _Owner] = {}
        for path, addresses in paths.addresses.items():
            winners = {_decide_chain(matcher, prefix + path) for prefix in prefixes}
            # The same question might be a direct lookup. A cached exclusion
            # must never remove a policy that protects the endpoint on its own.
            if inherited and (direct := _decide_chain(matcher, path)) is not None:
                winners.add(direct)
            winners.discard(None)
            if len(winners) > 1:
                raise RuntimeError("shared DNS alias has conflicting routing policies")
            if not winners:
                continue
            winner = winners.pop()
            assert winner is not None
            for address in addresses:
                if owners.setdefault(address, winner) != winner:
                    raise RuntimeError("shared DNS address has conflicting routing policies")
        for policy_id, drop in sorted(set(owners.values())):
            if self._callback is None:
                raise RuntimeError("DNS destination publication is unavailable")
            mine = [a for a, owner in owners.items() if owner == (policy_id, drop)]
            await self._callback(
                DestSet(
                    policy_id,
                    frozenset(a for a in mine if isinstance(a, IPv4Network)),
                    frozenset(a for a in mine if isinstance(a, IPv6Network)),
                    drop,
                )
            )

        # Even an unmatched prefix can contain an exclusion for the next hop.
        if not paths.aliases:
            return
        rows: AliasRows = {}
        now = time.monotonic()
        for path, ttl in paths.aliases.items():
            if inherited and _decide_chain(matcher, path) is not None:
                # A standalone protected lookup can itself return another alias.
                rows[path[-1], path[:-1]] = now + ttl
            for prefix, parent_expires in prefixes.items():
                combined = prefix + path
                if len(combined) > 128 or len(set(combined)) != len(combined):
                    raise RuntimeError("cyclic or oversized DNS alias chain")
                rows[path[-1], combined[:-1]] = min(now + ttl, parent_expires)
                if len(rows) > _MAX_ALIAS_ORIGINS:
                    raise RuntimeError("DNS alias tracking capacity exceeded")
        await asyncio.to_thread(
            self._aliases.remember, key, rows, time.monotonic(), _MAX_ALIAS_ORIGINS
        )
        # Cap the actual records that supplied the references, wherever they
        # appeared in the reply. Clients start their TTL clocks after this write.
        released = time.monotonic()
        inherited_until = min(prefixes.values())
        for path, rrset in paths.records:
            expires = min(now + paths.aliases[path], inherited_until)
            if expires <= released:
                raise RuntimeError("DNS alias expired before reply")
            rrset.ttl = min(rrset.ttl, int(expires - released))


class _UdpListener(asyncio.DatagramProtocol):
    def __init__(self, stub: _Stub) -> None:
        self.stub = stub
        self.transport: asyncio.DatagramTransport | None = None
        self.released = asyncio.Event()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)

    def connection_lost(self, exc: Exception | None) -> None:
        self.transport = None
        self.released.set()

    def datagram_received(self, data: bytes, addr: ClientAddress) -> None:
        self.stub.receive_udp(self, data, addr)


class _Stub:
    def __init__(self, service: PolicyDnsService, plan: PolicyPlan) -> None:
        self.service = service
        self.plan = plan
        self._udp: list[_UdpListener] = []
        self._tcp: list[asyncio.Server] = []
        self._udp_tasks: set[asyncio.Task[None]] = set()
        self._tcp_tasks: set[asyncio.Task[None]] = set()
        self._generation = 0
        self._closed = False

    async def open(self, port: int) -> None:
        loop = asyncio.get_running_loop()

        def new_listener() -> _UdpListener:
            listener = _UdpListener(self)
            self._udp.append(listener)
            return listener

        try:
            for address in _LISTEN_ADDRESSES:
                try:
                    await loop.create_datagram_endpoint(new_listener, local_addr=(address, port))
                except OSError as exc:
                    if address != "::1" or exc.errno not in _IPV6_UNAVAILABLE:
                        raise
                    log.debug("IPv6 loopback unavailable for DNS stub on port %d: %s", port, exc)
                    continue
                self._tcp.append(await asyncio.start_server(self._accept_tcp, address, port))
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        self._closed = True
        releases = []
        for listener in self._udp:
            transport = listener.transport
            if transport is not None:
                transport.close()
                # On Python 3.11 the selector datagram transport subclasses
                # BaseTransport rather than DatagramTransport.
                if isinstance(transport, asyncio.BaseTransport):
                    releases.append(listener.released)
        for server in self._tcp:
            server.close()
        self.cancel_queries()
        await asyncio.gather(*self._udp_tasks, *self._tcp_tasks, return_exceptions=True)
        await asyncio.gather(*(server.wait_closed() for server in self._tcp))
        # UDP sockets close on a later loop iteration. Wait so a restart can
        # bind the same port in both families without racing socket release.
        try:
            await asyncio.wait_for(
                asyncio.gather(*(released.wait() for released in releases)), _UDP_RELEASE_TIMEOUT
            )
        except TimeoutError:
            log.warning("DNS stub UDP sockets were not released within %ss", _UDP_RELEASE_TIMEOUT)

    def cancel_queries(self) -> None:
        self._generation += 1
        for task in self._udp_tasks | self._tcp_tasks:
            task.cancel()

    def receive_udp(self, listener: _UdpListener, data: bytes, addr: ClientAddress) -> None:
        if not self._closed and len(self._udp_tasks) < _MAX_UDP_QUERIES:
            task = asyncio.create_task(self._reply_udp(listener, data, addr))
            self._udp_tasks.add(task)
            task.add_done_callback(self._udp_tasks.discard)

    async def _reply_udp(self, listener: _UdpListener, data: bytes, addr: ClientAddress) -> None:
        reply = await self.answer(data, tcp=False)
        if reply is not None and not self._closed and listener.transport is not None:
            listener.transport.sendto(reply, addr)

    def _accept_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._closed or len(self._tcp_tasks) >= _MAX_TCP_CLIENTS:
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
        key: AliasKey = (plan.policy_id, question.rdclass, _domain(question.name))
        try:
            async with asyncio.timeout(_RESOLVE_TIMEOUT):
                inherited = await asyncio.to_thread(
                    self.service._aliases.origins, key, time.monotonic()
                )
                response = await self._resolve(plan, query)
                async with self.service._publication_lock:
                    inherited.update(
                        await asyncio.to_thread(
                            self.service._aliases.origins, key, time.monotonic()
                        )
                    )
                    if self._generation == generation:
                        await self.service._publish(plan, response, inherited, key)
                        response.id = query.id
                        if self._generation == generation:
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
        if not _narrow_dname(query, response):
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


def _narrow_dname(query: dns.message.Message, response: dns.message.Message) -> bool:
    """Expose only the synthesized CNAME that the policy matcher can track."""
    redirects = [rr for rr in response.answer if rr.rdtype == dns.rdatatype.DNAME]
    if any(rr.rdtype == dns.rdatatype.DNAME for rr in (*response.authority, *response.additional)):
        return False
    if not redirects:
        return True
    if (
        not isinstance(response, dns.message.QueryMessage)
        or response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
        or query.question[0].rdtype in (dns.rdatatype.DNAME, dns.rdatatype.ANY)
        or query.ednsflags & dns.flags.DO
        or query.flags & dns.flags.AD
    ):
        return False

    chain = response.resolve_chaining()
    cnames = list(chain.cnames)
    if chain.answer is not None and chain.answer.rdtype == dns.rdatatype.CNAME:
        cnames.append(chain.answer)
    for redirect in redirects:
        if len(redirect) != 1 or not any(
            alias.rdclass == redirect.rdclass
            and alias.name != redirect.name
            and alias.name.is_subdomain(redirect.name)
            and alias[0].target
            == alias.name.relativize(redirect.name).concatenate(redirect[0].target)
            for alias in cnames
        ):
            return False

    response.answer[:] = [
        rr
        for rr in response.answer
        if rr.rdtype != dns.rdatatype.DNAME and rr.covers != dns.rdatatype.DNAME
    ]
    if response.index is not None:
        for key, rr in list(response.index.items()):
            if key[0] == dns.message.MessageSection.ANSWER and (
                rr.rdtype == dns.rdatatype.DNAME or rr.covers == dns.rdatatype.DNAME
            ):
                del response.index[key]
    response.flags &= ~dns.flags.AD
    return True


def _domain(name: dns.name.Name) -> str:
    return name.canonicalize().to_text(omit_final_dot=True)


def _decide_chain(matcher: RuleMatcher, domains: DomainChain) -> _Owner | None:
    """The owner of a chain's addresses; a ``drop:`` match counts as one."""
    if isinstance(matcher, _DecidingMatcher):
        return matcher.decide_chain(*domains)
    policy_id = _match_chain(matcher, domains)
    return None if policy_id is None else (policy_id, False)


def _match_chain(matcher: RuleMatcher, domains: DomainChain) -> int | None:
    if isinstance(matcher, _ChainMatcher):
        return matcher.match_chain(*domains)
    # Phase 0 matchers can compare individual names. Policy IDs follow config order.
    matches = (matcher.match(domain) for domain in domains)
    return min((policy_id for policy_id in matches if policy_id is not None), default=None)


@dataclass
class _AnswerPaths:
    # The last name is the target. Every earlier link bounds its lifetime.
    aliases: dict[DomainChain, float] = field(default_factory=dict)
    records: list[tuple[DomainChain, RRset]] = field(default_factory=list)
    addresses: dict[DomainChain, set[IPv4Network | IPv6Network]] = field(
        default_factory=lambda: defaultdict(set)
    )

    def extend(self, path: DomainChain, target: dns.name.Name, rrset: RRset) -> DomainChain:
        name = _domain(target)
        if name in path or len(path) >= 128:
            raise ValueError("cyclic or oversized DNS alias chain")
        extended = (*path, name)
        self.aliases[extended] = min(
            self.aliases.get(path, float("inf")), rrset.ttl or _RESOLVE_TIMEOUT
        )
        self.records.append((extended, rrset))
        if len(self.aliases) > _MAX_ALIAS_ORIGINS:
            raise ValueError("too many DNS alias paths")
        return extended


def _referral(
    response: dns.message.QueryMessage, chain: dns.message.ChainingResult
) -> RRset | None:
    """A delegation names the servers for the closest enclosing zone."""
    if chain.answer is not None or response.rcode() != dns.rcode.NOERROR:
        return None
    rrclass = response.question[0].rdclass
    enclosing = [
        rrset
        for rrset in response.authority
        if rrset.rdclass == rrclass and chain.canonical_name.is_subdomain(rrset.name)
    ]
    if any(rrset.rdtype == dns.rdatatype.SOA for rrset in enclosing):
        return None
    return max(
        (rrset for rrset in enclosing if rrset.rdtype == dns.rdatatype.NS),
        key=lambda rrset: len(rrset.name),
        default=None,
    )


def _answer_paths(
    response: dns.message.QueryMessage, chain: dns.message.ChainingResult
) -> _AnswerPaths:
    """Keep the name path for each returned address, including service hints."""
    question = response.question[0]
    paths = _AnswerPaths()
    path: DomainChain = (_domain(question.name),)
    for rrset in chain.cnames:
        path = paths.extend(path, next(iter(rrset)).target, rrset)

    additional: dict[str, list[RRset]] = defaultdict(list)
    for rrset in response.additional:
        if rrset.rdclass == question.rdclass:
            additional[_domain(rrset.name)].append(rrset)
    answers = [
        rrset
        for rrset in response.answer
        if rrset.name == chain.canonical_name
        and rrset.rdclass == question.rdclass
        and (question.rdtype == dns.rdatatype.ANY or rrset.rdtype == question.rdtype)
    ]
    if not answers and (referral := _referral(response, chain)) is not None:
        answers.append(referral)
    pending = [(path, [*answers, *additional[path[-1]]])]
    visited: set[DomainChain] = set()
    while pending:
        path, records = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        for rrset in records:
            aliases = any(isinstance(r, SVCBBase) and r.priority == 0 for r in rrset)
            for record in rrset:
                if rrset.rdtype == dns.rdatatype.A:
                    paths.addresses[path].add(IPv4Network(str(record)))
                    continue
                if rrset.rdtype == dns.rdatatype.AAAA:
                    paths.addresses[path].add(IPv6Network(str(record)))
                    continue
                if isinstance(record, SVCBBase):
                    if aliases and record.priority != 0:
                        continue
                    target = record.target
                    if not record.priority and target == dns.name.root:
                        continue
                elif isinstance(record, (CNAME, NS, SRV)):
                    target = record.target
                elif isinstance(record, MX):
                    target = record.exchange
                else:
                    continue

                endpoint = path
                if target != dns.name.root and _domain(target) != path[-1]:
                    endpoint = paths.extend(path, target, rrset)
                    pending.append((endpoint, additional[endpoint[-1]]))
                elif isinstance(record, CNAME) or (
                    isinstance(record, SVCBBase) and not record.priority
                ):
                    raise ValueError("cyclic DNS alias")
                if isinstance(record, SVCBBase) and record.priority:
                    hint4 = record.params.get(ParamKey.IPV4HINT)
                    hint6 = record.params.get(ParamKey.IPV6HINT)
                    if isinstance(hint4, IPv4HintParam):
                        paths.addresses[endpoint].update(IPv4Network(a) for a in hint4.addresses)
                    if isinstance(hint6, IPv6HintParam):
                        paths.addresses[endpoint].update(IPv6Network(a) for a in hint6.addresses)
    return paths
