import asyncio
from dataclasses import replace
from ipaddress import ip_network
from unittest.mock import AsyncMock, Mock

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest

from pyvpn.audit import audit_dns
from pyvpn.dns import service as dns_service
from pyvpn.dns.service import PolicyDnsService, _Stub
from pyvpn.state import DestSet, PolicyPlan
from tests.dns._helpers import plan_for_dns as _plan
from tests.fakes.backend import FakeBackend
from tests.fakes.rules import FakeRuleMatcher


def _answer(query: dns.message.Message, address: str = "192.0.2.10") -> dns.message.Message:
    response = dns.message.make_response(query)
    response.answer.extend(
        [
            dns.rrset.from_text(query.question[0].name, 60, "IN", "CNAME", "edge.example."),
            dns.rrset.from_text("edge.example.", 60, "IN", query.question[0].rdtype, address),
            dns.rrset.from_text("unrelated.example.", 60, "IN", "A", "192.0.2.99"),
        ]
    )
    return dns.message.from_wire(response.to_wire())


@pytest.mark.parametrize(
    ("kind", "address", "dests"),
    [
        ("A", "192.0.2.10", DestSet(1, v4=frozenset({ip_network("192.0.2.10/32")}))),
        ("AAAA", "2001:db8::1", DestSet(1, v6=frozenset({ip_network("2001:db8::1/128")}))),
    ],
)
@pytest.mark.parametrize("matched_name", ["selected.example", "edge.example"])
@pytest.mark.parametrize(("filtered", "winner"), [(True, 1), (True, 2), (False, 2)])
def test_waits_for_destination_publication_before_answering(
    kind: str,
    address: str,
    dests: DestSet,
    matched_name: str,
    filtered: bool,
    winner: int,
) -> None:
    async def run() -> None:
        entered = asyncio.Event()
        release = asyncio.Event()
        backend = FakeBackend()
        expected = replace(dests, policy_id=winner)

        async def publish(value: DestSet) -> None:
            assert value == expected
            entered.set()
            await release.wait()
            await backend.add_to_set(value)

        plan = replace(_plan(), dests=DestSet(1) if filtered else None)
        upstream = AsyncMock(side_effect=lambda _, q: _answer(q, address))
        matcher = FakeRuleMatcher({matched_name: winner})
        service = PolicyDnsService(upstream, matcher_factory=lambda: matcher)
        service.on_answer(publish)
        stub = _Stub(service, plan)
        query = dns.message.make_query("Selected.Example.", kind)
        task = asyncio.create_task(stub.answer(query.to_wire(), tcp=False))

        await asyncio.wait_for(entered.wait(), 1)
        assert not task.done()
        release.set()
        reply = dns.message.from_wire(await task)
        assert query.is_response(reply)
        assert reply.rcode() == dns.rcode.NOERROR
        assert reply.answer[1][0].address == address
        assert backend.sets == [expected]
        assert upstream.await_args.args[0].interface == "wg-jp"

    asyncio.run(run())


@pytest.mark.parametrize("winner", [1, None])
def test_chain_matcher_gets_all_cnames_and_controls_publication(winner: int | None) -> None:
    async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.answer.extend(
            [
                dns.rrset.from_text(query.question[0].name, 60, "IN", "CNAME", "Hop.Example."),
                dns.rrset.from_text("Hop.Example.", 60, "IN", "CNAME", "Edge.Example."),
                dns.rrset.from_text("Edge.Example.", 60, "IN", "A", "192.0.2.10"),
                dns.rrset.from_text("unrelated.example.", 60, "IN", "CNAME", "ignored.example."),
            ]
        )
        return dns.message.from_wire(response.to_wire())

    class ChainMatcher(FakeRuleMatcher):
        def match_chain(self, *names: str) -> int | None:
            assert names == ("selected.example", "hop.example", "edge.example")
            return winner

    matcher = ChainMatcher({"selected.example": 1})
    service = PolicyDnsService(upstream, matcher_factory=lambda: matcher)
    backend = FakeBackend()
    service.on_answer(backend.add_to_set)
    query = dns.message.make_query("Selected.Example.", "A")
    plan = replace(_plan(), dests=DestSet(1))

    wire = asyncio.run(_Stub(service, plan).answer(query.to_wire(), tcp=False))

    assert dns.message.from_wire(wire).rcode() == dns.rcode.NOERROR
    expected = [DestSet(1, v4=frozenset({ip_network("192.0.2.10/32")}))] if winner else []
    assert backend.sets == expected


@pytest.mark.parametrize("winner", [1, 2])
def test_failed_publication_returns_servfail_without_answer_records(winner: int) -> None:
    plan = replace(_plan(), dests=DestSet(1))
    service = PolicyDnsService(
        AsyncMock(side_effect=lambda _, query: _answer(query)),
        matcher_factory=lambda: FakeRuleMatcher({"selected.example": winner}),
    )
    backend = FakeBackend()
    backend.fail_add = True
    service.on_answer(backend.add_to_set)
    query = dns.message.make_query("selected.example.", "A")

    wire = asyncio.run(_Stub(service, plan).answer(query.to_wire(), tcp=False))
    reply = dns.message.from_wire(wire)
    assert query.is_response(reply)
    assert reply.rcode() == dns.rcode.SERVFAIL
    assert not reply.answer


def test_https_hints_and_additional_target_addresses_are_installed_before_reply() -> None:
    async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.answer.append(
            dns.rrset.from_text(
                "selected.example.",
                60,
                "IN",
                "HTTPS",
                "1 edge.example. ipv4hint=192.0.2.10 ipv6hint=2001:db8::1",
            )
        )
        response.additional.extend(
            [
                dns.rrset.from_text("edge.example.", 60, "IN", "A", "192.0.2.11"),
                dns.rrset.from_text("edge.example.", 60, "IN", "AAAA", "2001:db8::2"),
                dns.rrset.from_text("unrelated.example.", 60, "IN", "A", "192.0.2.99"),
            ]
        )
        return dns.message.from_wire(response.to_wire())

    service = PolicyDnsService(
        upstream, matcher_factory=lambda: FakeRuleMatcher({"selected.example": 1})
    )
    backend = FakeBackend()
    service.on_answer(backend.add_to_set)
    query = dns.message.make_query("selected.example.", "HTTPS")
    policy = replace(_plan(), dests=DestSet(1))

    wire = asyncio.run(_Stub(service, policy).answer(query.to_wire(), tcp=False))
    assert dns.message.from_wire(wire).rcode() == dns.rcode.NOERROR
    assert backend.sets == [
        DestSet(
            1,
            v4=frozenset({ip_network("192.0.2.10"), ip_network("192.0.2.11")}),
            v6=frozenset({ip_network("2001:db8::1"), ip_network("2001:db8::2")}),
        )
    ]


def test_unmatched_domains_do_not_add_addresses_to_any_policy_set() -> None:
    plan = replace(_plan(), dests=DestSet(1))
    service = PolicyDnsService(
        AsyncMock(side_effect=lambda _, query: _answer(query)),
        matcher_factory=lambda: FakeRuleMatcher({}),
    )
    update = AsyncMock()
    service.on_answer(update)
    query = dns.message.make_query("selected.example.", "A")

    wire = asyncio.run(_Stub(service, plan).answer(query.to_wire(), tcp=False))
    assert dns.message.from_wire(wire).rcode() == dns.rcode.NOERROR
    update.assert_not_awaited()


def test_missing_matcher_fails_closed_for_a_filtered_answer() -> None:
    plan = replace(_plan(), dests=DestSet(1))
    service = PolicyDnsService(AsyncMock(side_effect=lambda _, query: _answer(query)))
    update = AsyncMock()
    service.on_answer(update)
    query = dns.message.make_query("selected.example.", "A")

    wire = asyncio.run(_Stub(service, plan).answer(query.to_wire(), tcp=False))

    assert dns.message.from_wire(wire).rcode() == dns.rcode.SERVFAIL
    update.assert_not_awaited()


@pytest.mark.parametrize("route", ["main", "unreachable"])
def test_no_upstream_when_target_is_unavailable(route: str) -> None:
    plan = replace(_plan(), route=route, interface=None)
    upstream = AsyncMock()
    query = dns.message.make_query("selected.example.", "A")

    wire = asyncio.run(_Stub(PolicyDnsService(upstream), plan).answer(query.to_wire(), tcp=False))
    assert dns.message.from_wire(wire).rcode() == dns.rcode.SERVFAIL
    upstream.assert_not_awaited()


def test_firefox_canary_is_answered_locally() -> None:
    upstream = AsyncMock()
    query = dns.message.make_query("Use-Application-DNS.NET.", "A")
    stub = _Stub(PolicyDnsService(upstream), _plan(block_doh=True))

    wire = asyncio.run(stub.answer(query.to_wire(), tcp=False))
    assert dns.message.from_wire(wire).rcode() == dns.rcode.NXDOMAIN
    upstream.assert_not_awaited()


def test_upstream_binding_failure_returns_servfail() -> None:
    upstream = AsyncMock(side_effect=OSError("interface unavailable"))
    query = dns.message.make_query("selected.example.", "A")
    stub = _Stub(PolicyDnsService(upstream), _plan())

    wire = asyncio.run(stub.answer(query.to_wire(), tcp=False))
    assert dns.message.from_wire(wire).rcode() == dns.rcode.SERVFAIL
    upstream.assert_awaited_once()


def test_invalid_response_id_is_rejected() -> None:
    async def wrong_id(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        response = _answer(query)
        response.id ^= 1
        return response

    query = dns.message.make_query("selected.example.", "A")
    stub = _Stub(PolicyDnsService(wrong_id), _plan())
    wire = asyncio.run(stub.answer(query.to_wire(), tcp=False))
    assert dns.message.from_wire(wire).rcode() == dns.rcode.SERVFAIL


def test_tcp_accepts_dns_frames_and_udp_truncates_to_client_size() -> None:
    async def run() -> None:
        async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
            response = dns.message.make_response(query)
            records = ['"' + c * 250 + '"' for c in "abc"]
            response.answer.append(dns.rrset.from_text("example.", 60, "IN", "TXT", *records))
            return response

        stub = _Stub(PolicyDnsService(upstream), _plan())
        query = dns.message.make_query("example.", "TXT")
        wire = query.to_wire()
        reply = await stub.answer(wire, tcp=False)
        assert len(reply) <= 512
        assert dns.message.from_wire(reply).flags & dns.flags.TC

        reader = asyncio.StreamReader()
        reader.feed_data(len(wire).to_bytes(2, "big") + wire)
        reader.feed_eof()
        writer = Mock(drain=AsyncMock())
        await stub._reply_tcp(reader, writer)
        framed = writer.write.call_args.args[0]
        assert int.from_bytes(framed[:2], "big") == len(framed[2:])
        assert not dns.message.from_wire(framed[2:]).flags & dns.flags.TC

    asyncio.run(run())


def test_idle_tcp_limit_does_not_starve_udp(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        sent = asyncio.Event()
        monkeypatch.setattr(dns_service, "_MAX_TCP_CLIENTS", 1)
        upstream = AsyncMock(side_effect=lambda _, query: _answer(query))
        stub = _Stub(PolicyDnsService(upstream), _plan())
        udp = Mock(sendto=Mock(side_effect=lambda *_: sent.set()))
        stub.connection_made(udp)
        idle_client = Mock()
        refused_client = Mock()
        stub._accept_tcp(asyncio.StreamReader(), idle_client)
        stub._accept_tcp(asyncio.StreamReader(), refused_client)
        query = dns.message.make_query("selected.example.", "A")
        try:
            refused_client.close.assert_called_once()
            stub.datagram_received(query.to_wire(), ("127.0.0.1", 49999))
            await asyncio.wait_for(sent.wait(), 1)
            reply = dns.message.from_wire(udp.sendto.call_args.args[0])
            assert query.is_response(reply)
            assert reply.rcode() == dns.rcode.NOERROR
            idle_client.close.assert_not_called()
        finally:
            await stub.close()

    asyncio.run(run())


def test_target_change_cancels_inflight_query_and_reuses_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        started = asyncio.Event()
        sent = asyncio.Event()
        cancelled = asyncio.Event()
        previous = _plan()
        next_plan = replace(previous, interface="wg-nl")
        transport = Mock(sendto=Mock(side_effect=lambda *_: sent.set()))
        server = Mock(wait_closed=AsyncMock())

        async def listen_udp(factory: object, *, local_addr: tuple[str, int]) -> None:
            assert local_addr == ("127.0.0.1", 5301)
            factory().connection_made(transport)

        async def upstream(plan: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
            assert plan is previous
            started.set()
            try:
                await asyncio.Future()
            finally:
                cancelled.set()
            return _answer(query)

        loop = asyncio.get_running_loop()
        udp = AsyncMock(side_effect=listen_udp)
        tcp = AsyncMock(return_value=server)
        monkeypatch.setattr(loop, "create_datagram_endpoint", udp)
        monkeypatch.setattr(asyncio, "start_server", tcp)
        service = PolicyDnsService(upstream)
        await service.start(previous)
        stub = service._stubs[1]
        query = dns.message.make_query("selected.example.", "A")
        stub.datagram_received(query.to_wire(), ("127.0.0.1", 49999))
        await asyncio.wait_for(started.wait(), 1)
        await service.start(next_plan)
        await asyncio.wait_for(sent.wait(), 1)

        assert cancelled.is_set()
        assert service.is_listening(1)
        assert service._stubs[1] is stub
        udp.assert_awaited_once()
        tcp.assert_awaited_once_with(stub._accept_tcp, "127.0.0.1", 5301)
        wire = transport.sendto.call_args.args[0]
        assert dns.message.from_wire(wire).rcode() == dns.rcode.SERVFAIL
        await service.stop(1)
        assert not service.is_listening(1)
        transport.close.assert_called_once()
        server.close.assert_called_once()

    asyncio.run(run())


def test_tcp_bind_failure_closes_udp_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        transport = Mock()

        async def open_udp(factory: object, **_: object) -> None:
            factory().connection_made(transport)

        monkeypatch.setattr(asyncio.get_running_loop(), "create_datagram_endpoint", open_udp)
        monkeypatch.setattr(asyncio, "start_server", AsyncMock(side_effect=OSError("port in use")))
        service = PolicyDnsService(AsyncMock())
        with pytest.raises(OSError, match="port in use"):
            await service.start(_plan())
        assert not service.is_listening(1)
        transport.close.assert_called_once()

    asyncio.run(run())


def test_audit_reports_listener_and_requested_packet_blocks_separately() -> None:
    plan = _plan(block_quic=True, block_doh=True)
    active = audit_dns(plan, listening=True)
    assert active.stub_listening
    assert active.upstream_interface == "wg-jp"
    assert active.upstream_problem is None
    assert active.firefox_canary
    assert active.requested_packet_blocks == ("DoH", "QUIC")
    assert not audit_dns(plan, listening=False).firefox_canary
    assert audit_dns(replace(plan, route="main"), listening=True).upstream_interface is None
