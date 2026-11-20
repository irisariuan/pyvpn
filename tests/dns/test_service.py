import asyncio
from dataclasses import replace
from ipaddress import ip_network
from pathlib import Path
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


@pytest.fixture(autouse=True)
def isolated_alias_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dns_service, "_ALIAS_PATH", tmp_path / "dns-aliases.sqlite3")


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


@pytest.mark.parametrize("winner", [1, 3, None], ids=["own-policy", "global-policy", "unmatched"])
def test_scopes_active_matcher_to_requesting_stub(winner: int | None) -> None:
    class ActiveMatcher(FakeRuleMatcher):
        def scoped(self, policy_id: int) -> FakeRuleMatcher:
            assert policy_id == 1
            return FakeRuleMatcher({"edge.example": winner} if winner is not None else {})

    plan = replace(_plan(), dests=DestSet(1))
    service = PolicyDnsService(
        AsyncMock(side_effect=lambda _, query: _answer(query)),
        matcher_factory=lambda: ActiveMatcher({"selected.example": 2}),
    )
    backend = FakeBackend()
    service.on_answer(backend.add_to_set)
    query = dns.message.make_query("selected.example.", "A")

    wire = asyncio.run(_Stub(service, plan).answer(query.to_wire(), tcp=False))

    assert dns.message.from_wire(wire).rcode() == dns.rcode.NOERROR
    expected = [] if winner is None else [DestSet(winner, v4=frozenset({ip_network("192.0.2.10")}))]
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


@pytest.mark.parametrize(
    ("kind", "alias", "fail_publication"),
    [("HTTPS", False, False), ("HTTPS", True, False), ("SVCB", True, False), ("HTTPS", True, True)],
)
def test_service_binding_endpoint_addresses_are_published(
    kind: str, alias: bool, fail_publication: bool
) -> None:
    async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        address_owner = "edge.example."
        service = dns.rrset.from_text(
            "svc.example." if alias else "selected.example.",
            60,
            "IN",
            kind,
            "1 edge.example. ipv4hint=192.0.2.10 ipv6hint=2001:db8::1",
        )
        if alias:
            address_owner = "node.example."
            response.answer.append(
                dns.rrset.from_text("selected.example.", 60, "IN", kind, "0 first.example.")
            )
            response.additional.extend(
                [
                    dns.rrset.from_text("first.example.", 60, "IN", "CNAME", "hop.example."),
                    dns.rrset.from_text("hop.example.", 60, "IN", kind, "0 svc.example."),
                    service,
                    dns.rrset.from_text("edge.example.", 60, "IN", "CNAME", address_owner),
                ]
            )
        else:
            response.answer.append(service)
        response.additional.extend(
            [
                dns.rrset.from_text(address_owner, 60, "IN", "A", "192.0.2.11"),
                dns.rrset.from_text(address_owner, 60, "IN", "AAAA", "2001:db8::2"),
                dns.rrset.from_text("unrelated.example.", 60, "IN", "A", "192.0.2.99"),
                dns.rrset.from_text(
                    "unrelated.example.", 60, "IN", kind, "1 . ipv4hint=192.0.2.98"
                ),
            ]
        )
        return dns.message.from_wire(response.to_wire())

    service = PolicyDnsService(
        upstream, matcher_factory=lambda: FakeRuleMatcher({"selected.example": 1})
    )
    backend = FakeBackend()
    backend.fail_add = fail_publication
    service.on_answer(backend.add_to_set)
    query = dns.message.make_query("selected.example.", kind)
    policy = replace(_plan(), dests=DestSet(1))

    wire = asyncio.run(_Stub(service, policy).answer(query.to_wire(), tcp=True))
    reply = dns.message.from_wire(wire)
    assert query.is_response(reply)
    if fail_publication:
        assert reply.rcode() == dns.rcode.SERVFAIL
        assert not reply.answer
        assert not reply.additional
        return
    assert reply.rcode() == dns.rcode.NOERROR
    assert backend.sets == [
        DestSet(
            1,
            v4=frozenset({ip_network("192.0.2.10"), ip_network("192.0.2.11")}),
            v6=frozenset({ip_network("2001:db8::1"), ip_network("2001:db8::2")}),
        )
    ]


@pytest.mark.parametrize(("kind", "address"), [("A", "192.0.2.10"), ("AAAA", "2001:db8::2")])
@pytest.mark.parametrize("with_address", [False, True], ids=["split-answer", "cached-cname"])
def test_address_followup_uses_cname_origin_until_expiry(
    monkeypatch: pytest.MonkeyPatch, kind: str, address: str, with_address: bool
) -> None:
    clock = Mock(return_value=100.0)
    monkeypatch.setattr(dns_service, "time", clock)

    async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        owner = query.question[0].name
        reply = dns.message.make_response(query)
        if owner == dns.name.from_text("selected.example."):
            reply.answer.append(dns.rrset.from_text(owner, 4, "IN", "CNAME", "edge.example."))
        if with_address or not reply.answer:
            reply.answer.append(dns.rrset.from_text("edge.example.", 1, "IN", kind, address))
        return dns.message.from_wire(reply.to_wire())

    async def run() -> None:
        matcher = FakeRuleMatcher({"selected.example": 1})
        service = PolicyDnsService(upstream, matcher_factory=lambda: matcher)
        backend = FakeBackend()
        service.on_answer(backend.add_to_set)
        stub = _Stub(service, replace(_plan(), dests=DestSet(1)))

        async def lookup(name: str) -> dns.message.Message:
            query = dns.message.make_query(name, kind)
            return dns.message.from_wire(await stub.answer(query.to_wire(), tcp=False))

        assert (await lookup("selected.example.")).rcode() == dns.rcode.NOERROR
        clock.return_value = 102.0
        backend.sets.clear()
        backend.fail_add = True
        failed = await lookup("edge.example.")
        assert failed.rcode() == dns.rcode.SERVFAIL
        assert not failed.answer

        backend.fail_add = False
        reply = await lookup("edge.example.")
        assert reply.answer[0][0].address == address
        [published] = backend.sets
        assert published.policy_id == 1
        assert published.v4 | published.v6 == {ip_network(address)}

        clock.return_value = 104.0
        backend.sets.clear()
        assert (await lookup("edge.example.")).rcode() == dns.rcode.NOERROR
        assert not backend.sets

    asyncio.run(run())


@pytest.mark.parametrize("kind", ["HTTPS", "SVCB"])
def test_service_alias_followups_keep_the_original_policy(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Mock(return_value=100.0)
    monkeypatch.setattr(dns_service, "time", clock)
    monkeypatch.setattr(dns_service, "_MAX_ALIAS_ORIGINS", 3)

    async def run() -> None:
        answers = {
            ("selected.example.", kind): (kind, "0 svc.example."),
            ("second.example.", kind): (kind, "0 other.example."),
            ("svc.example.", kind): (kind, "1 edge.example. ipv4hint=192.0.2.10"),
            ("edge.example.", "AAAA"): ("AAAA", "2001:db8::2"),
        }

        async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
            question = query.question[0]
            owner = question.name.to_text()
            record_type, value = answers[owner, dns.rdatatype.to_text(question.rdtype)]
            reply = dns.message.make_response(query)
            reply.answer.append(dns.rrset.from_text(owner, 60, "IN", record_type, value))
            return dns.message.from_wire(reply.to_wire())

        matcher = FakeRuleMatcher({"selected.example": 1, "second.example": 1})
        service = PolicyDnsService(upstream, matcher_factory=lambda: matcher)
        backend = FakeBackend()
        service.on_answer(backend.add_to_set)
        plan = replace(_plan(), dests=DestSet(1))
        stub = _Stub(service, plan)
        other_stub = _Stub(service, replace(plan, policy_id=2, dests=DestSet(2)))

        async def query(stub: _Stub, name: str, rdtype: str) -> dns.message.Message:
            request = dns.message.make_query(name, rdtype)
            wire = await stub.answer(request.to_wire(), tcp=True)
            reply = dns.message.from_wire(wire)
            assert request.is_response(reply)
            return reply

        assert (await query(stub, "selected.example.", kind)).rcode() == dns.rcode.NOERROR
        assert not backend.sets
        assert (await query(other_stub, "svc.example.", kind)).rcode() == dns.rcode.NOERROR
        assert not backend.sets
        # An active follow-up must still carry the origin's policy after recreating the listener.
        stub = _Stub(service, plan)
        matcher.domains["svc.example"] = 2
        conflict = await query(stub, "svc.example.", kind)
        assert conflict.rcode() == dns.rcode.SERVFAIL
        assert not conflict.answer
        assert not backend.sets
        del matcher.domains["svc.example"]
        assert (await query(stub, "svc.example.", kind)).rcode() == dns.rcode.NOERROR
        assert backend.sets == [DestSet(1, v4=frozenset({ip_network("192.0.2.10")}))]
        full = await query(stub, "second.example.", kind)
        assert full.rcode() == dns.rcode.SERVFAIL
        assert not full.answer

        backend.fail_add = True
        failed = await query(stub, "edge.example.", "AAAA")
        assert failed.rcode() == dns.rcode.SERVFAIL
        assert not failed.answer
        backend.fail_add = False
        assert (await query(stub, "edge.example.", "AAAA")).rcode() == dns.rcode.NOERROR
        assert backend.sets[-1] == DestSet(1, v6=frozenset({ip_network("2001:db8::2")}))

        # A reload can change the origin's winner without retaining a stale policy ID.
        matcher.domains["selected.example"] = 2
        assert (await query(stub, "edge.example.", "AAAA")).rcode() == dns.rcode.NOERROR
        assert backend.sets[-1].policy_id == 2

        clock.return_value = 161.0
        backend.sets.clear()
        assert (await query(stub, "edge.example.", "AAAA")).rcode() == dns.rcode.NOERROR
        assert not backend.sets
        assert (await query(stub, "second.example.", kind)).rcode() == dns.rcode.NOERROR

    asyncio.run(run())


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


@pytest.mark.parametrize("first_type", ["A", "AAAA", "CNAME"])
@pytest.mark.parametrize("restart", [False, True], ids=["same-service", "fresh-service"])
@pytest.mark.parametrize(
    "excluded", [False, True], ids=["earlier-endpoint-rule", "excluded-endpoint"]
)
def test_split_and_combined_chains_select_the_same_policy(
    tmp_path: Path, first_type: str, restart: bool, excluded: bool
) -> None:
    backend = FakeBackend()
    plan = replace(_plan(), policy_id=2, dests=DestSet(2))
    endpoint_type, address = ("AAAA", "2001:db8::2") if first_type == "AAAA" else ("A", "192.0.2.1")
    records = [
        dns.rrset.from_text("origin.example.", 60, "IN", "CNAME", "middle.example."),
        dns.rrset.from_text("middle.example.", 60, "IN", "CNAME", "edge.example."),
        dns.rrset.from_text("edge.example.", 10, "IN", endpoint_type, address),
    ]

    class Matcher(FakeRuleMatcher):
        def match_chain(self, *names: str) -> int | None:
            if excluded:
                if "origin.example" in names and "edge.example" not in names:
                    return 1
            elif "edge.example" in names:
                return 1
            return 2 if "origin.example" in names else None

    def listener(path: Path, *, split: bool) -> _Stub:
        async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
            response = dns.message.make_response(query)
            i = next(i for i, rr in enumerate(records) if rr.name == query.question[0].name)
            response.answer.extend(records[i : i + 1] if split else records[i:])
            return dns.message.from_wire(response.to_wire())

        service = PolicyDnsService(upstream, alias_path=path, matcher_factory=Matcher)
        service.on_answer(backend.add_to_set)
        return _Stub(service, plan)

    async def lookup(stub: _Stub, name: str, kind: str) -> None:
        request = dns.message.make_query(name, kind)
        response = dns.message.from_wire(await stub.answer(request.to_wire(), tcp=False))
        assert response.rcode() == dns.rcode.NOERROR
        assert response.answer

    async def run() -> None:
        whole = listener(tmp_path / "whole.db", split=False)
        await lookup(whole, "origin.example.", endpoint_type)
        [expected] = backend.sets
        assert expected.policy_id == (2 if excluded else 1)
        backend.sets.clear()

        path = tmp_path / "split.db"
        stub = listener(path, split=True)
        await lookup(stub, "origin.example.", first_type)
        if restart:
            stub = listener(path, split=True)
        await lookup(stub, "middle.example.", first_type)
        if restart:
            stub = listener(path, split=True)
        await lookup(stub, "edge.example.", endpoint_type)
        assert backend.sets == [expected]

    asyncio.run(run())


def test_unavailable_alias_store_withholds_answer(tmp_path: Path) -> None:
    path = tmp_path / "aliases.db"
    service = PolicyDnsService(
        AsyncMock(side_effect=lambda _, q: _answer(q)),
        alias_path=path,
        matcher_factory=lambda: FakeRuleMatcher({"selected.example": 1}),
    )

    # A database write fails after the query and its origin have been read.
    async def fail_write(_: DestSet) -> None:
        path.unlink()

    service.on_answer(fail_write)
    wire = asyncio.run(
        _Stub(service, _plan()).answer(
            dns.message.make_query("selected.example.", "A").to_wire(), tcp=True
        )
    )
    reply = dns.message.from_wire(wire)
    assert reply.rcode() == dns.rcode.SERVFAIL
    assert not reply.answer


@pytest.mark.parametrize("kind", ["HTTPS", "SVCB"])
def test_earlier_endpoint_policy_wins_for_bundled_and_split_hints(
    tmp_path: Path, kind: str
) -> None:
    backend = FakeBackend()
    matcher = FakeRuleMatcher({"office.example": 2, "edge.example": 1})
    binding = dns.rrset.from_text("edge.example.", 30, "IN", kind, "1 . ipv4hint=192.0.2.8")

    async def run(bundled: bool) -> None:
        async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
            reply = dns.message.make_response(query)
            if query.question[0].name == binding.name:
                reply.answer.append(binding)
            else:
                reply.answer.append(
                    dns.rrset.from_text("office.example.", 60, "IN", kind, "0 edge.example.")
                )
                if bundled:
                    reply.additional.append(binding)
            return dns.message.from_wire(reply.to_wire())

        path = tmp_path / f"{bundled}.sqlite3"

        def listener() -> _Stub:
            service = PolicyDnsService(upstream, alias_path=path, matcher_factory=lambda: matcher)
            service.on_answer(backend.add_to_set)
            return _Stub(service, replace(_plan(), policy_id=2, dests=DestSet(2)))

        async def lookup(stub: _Stub, name: str) -> None:
            wire = await stub.answer(dns.message.make_query(name, kind).to_wire(), tcp=True)
            assert dns.message.from_wire(wire).rcode() == dns.rcode.NOERROR

        await lookup(listener(), "edge.example.")
        await lookup(listener(), "office.example.")
        await lookup(listener(), "edge.example.")
        expected = DestSet(1, v4=frozenset({ip_network("192.0.2.8")}))
        assert backend.sets == [expected] * (3 if bundled else 2)

    asyncio.run(run(False))
    backend.sets.clear()
    asyncio.run(run(True))


@pytest.mark.parametrize("kind", ["A", "AAAA"])
def test_excluded_alias_cannot_suppress_direct_policy(kind: str) -> None:
    class Matcher(FakeRuleMatcher):
        def match_chain(self, *names: str) -> int | None:
            if "edge.example" in names and "excluded.example" not in names:
                return 1
            return None

    async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        name = query.question[0].name
        if name == dns.name.from_text("excluded.example."):
            data = ("CNAME", "edge.example.")
        else:
            data = (kind, "192.0.2.1" if kind == "A" else "2001:db8::1")
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name, 60, "IN", *data))
        return dns.message.from_wire(response.to_wire())

    async def run() -> None:
        backend = FakeBackend()
        service = PolicyDnsService(upstream, matcher_factory=Matcher)
        service.on_answer(backend.add_to_set)
        stub = _Stub(service, _plan())

        async def lookup(name: str) -> dns.message.Message:
            wire = await stub.answer(dns.message.make_query(name, kind).to_wire(), tcp=False)
            return dns.message.from_wire(wire)

        assert (await lookup("edge.example.")).rcode() == dns.rcode.NOERROR
        assert [ds.policy_id for ds in backend.sets] == [1]
        backend.sets.clear()
        assert (await lookup("excluded.example.")).rcode() == dns.rcode.NOERROR
        reply = await lookup("edge.example.")
        assert reply.rcode() == dns.rcode.SERVFAIL
        assert not reply.answer
        assert not backend.sets

    asyncio.run(run())


@pytest.mark.parametrize("delay", [0.0, 1.25, 3.0, 4.0])
@pytest.mark.parametrize("kind", ["CNAME", "HTTPS", "SVCB"])
def test_reply_ttl_accounts_for_durable_write(
    delay: float, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Mock(return_value=100.0)
    monkeypatch.setattr(dns_service, "time", clock)

    async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        name = query.question[0].name
        response = dns.message.make_response(query)
        if name == dns.name.from_text("selected.example."):
            target = "edge.example." if kind == "CNAME" else "0 edge.example."
            record = dns.rrset.from_text(name, 3, "IN", kind, target)
        else:
            record = dns.rrset.from_text(name, 300, "IN", "A", "192.0.2.1")
        response.answer.append(record)
        return dns.message.from_wire(response.to_wire())

    async def run() -> None:
        service = PolicyDnsService(
            upstream, matcher_factory=lambda: FakeRuleMatcher({"selected.example": 1})
        )
        backend = FakeBackend()
        service.on_answer(backend.add_to_set)
        stub = _Stub(service, _plan())
        remember = service._aliases.remember

        def slow_write(*args: object) -> None:
            remember(*args)
            clock.return_value += delay

        monkeypatch.setattr(service._aliases, "remember", slow_write)
        query = dns.message.make_query("selected.example.", kind)
        wire = await stub.answer(query.to_wire(), tcp=True)
        reply = dns.message.from_wire(wire)
        if delay >= 3:
            assert reply.rcode() == dns.rcode.SERVFAIL
            assert not reply.answer
            return
        assert reply.rcode() == dns.rcode.NOERROR
        assert reply.answer[0].ttl == int(3 - delay)
        query = dns.message.make_query("edge.example.", "A")
        wire = await stub.answer(query.to_wire(), tcp=True)
        assert dns.message.from_wire(wire).answer[0].ttl == 300
        assert [ds.policy_id for ds in backend.sets] == [1]

    asyncio.run(run())


def test_alias_ttl_limits_each_link_after_a_split_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = Mock(return_value=100.0)
    monkeypatch.setattr(dns_service, "time", clock)

    async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        name = query.question[0].name
        reply = dns.message.make_response(query)
        if name == dns.name.from_text("selected.example."):
            reply.answer.append(dns.rrset.from_text(name, 10, "IN", "CNAME", "service.example."))
        else:
            reply.answer.append(dns.rrset.from_text(name, 60, "IN", "HTTPS", "0 svc.example."))
            reply.additional.append(
                dns.rrset.from_text("svc.example.", 2, "IN", "HTTPS", "1 edge.example.")
            )
            reply.additional.append(
                dns.rrset.from_text("edge.example.", 300, "IN", "A", "192.0.2.1")
            )
        return dns.message.from_wire(reply.to_wire())

    async def run() -> None:
        service = PolicyDnsService(
            upstream, matcher_factory=lambda: FakeRuleMatcher({"selected.example": 1})
        )
        backend = FakeBackend()
        service.on_answer(backend.add_to_set)
        stub = _Stub(service, _plan())

        async def ask(name: str) -> dns.message.Message:
            wire = await stub.answer(dns.message.make_query(name, "HTTPS").to_wire(), tcp=False)
            return dns.message.from_wire(wire)

        assert (await ask("selected.example.")).answer[0].ttl == 10
        clock.return_value = 106.5
        reply = await ask("service.example.")
        assert reply.rcode() == dns.rcode.NOERROR
        assert reply.answer[0].ttl == 3
        assert [rr.ttl for rr in reply.additional] == [2, 300]
        assert [ds.policy_id for ds in backend.sets] == [1]

    asyncio.run(run())


@pytest.mark.parametrize(
    ("query_type", "record_type", "value", "rcode"),
    [
        ("SRV", "SRV", "0 5 443 edge.example.", dns.rcode.NOERROR),
        ("MX", "MX", "10 edge.example.", dns.rcode.NOERROR),
        ("NS", "NS", "edge.example.", dns.rcode.NOERROR),
        ("TXT", "CNAME", "edge.example.", dns.rcode.NOERROR),
        ("A", "CNAME", "edge.example.", dns.rcode.NXDOMAIN),
    ],
)
@pytest.mark.parametrize(("family", "address"), [("A", "192.0.2.1"), ("AAAA", "2001:db8::1")])
def test_cached_endpoint_keeps_policy_across_query_types(
    tmp_path: Path,
    query_type: str,
    record_type: str,
    value: str,
    rcode: int,
    family: str,
    address: str,
) -> None:
    """Bundled addresses and later lookups must both be governed before release."""
    origin = "origin.example."
    endpoint = "edge.example."
    plan = replace(_plan(), dests=DestSet(1))
    matcher = FakeRuleMatcher({"origin.example": 1})
    backend = FakeBackend()
    expected = DestSet(1, **{"v4" if family == "A" else "v6": frozenset({ip_network(address)})})

    async def exercise(bundled: bool) -> None:
        path = tmp_path / f"aliases-{bundled}.db"

        async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
            response = dns.message.make_response(query)
            addr = dns.rrset.from_text(endpoint, 60, "IN", family, address)
            if query.question[0].name == dns.name.from_text(origin):
                response.answer.append(dns.rrset.from_text(origin, 120, "IN", record_type, value))
                response.set_rcode(rcode)
                if bundled:
                    response.additional.append(addr)
            else:
                response.answer.append(addr)
            return dns.message.from_wire(response.to_wire())

        async def query(name: str, kind: str) -> dns.message.Message:
            service = PolicyDnsService(upstream, alias_path=path, matcher_factory=lambda: matcher)
            service.on_answer(backend.add_to_set)
            wire = await _Stub(service, plan).answer(
                dns.message.make_query(name, kind).to_wire(), tcp=True
            )
            return dns.message.from_wire(wire)

        first = await query(origin, query_type)
        assert first.rcode() == rcode
        assert first.answer[0].rdtype == dns.rdatatype.from_text(record_type)
        assert backend.sets == ([expected] if bundled else [])
        backend.sets.clear()

        backend.fail_add = True
        failed = await query(endpoint, family)
        assert failed.rcode() == dns.rcode.SERVFAIL
        assert not failed.answer
        backend.fail_add = False
        final = await query(endpoint, family)
        assert final.answer[0][0].address == address
        assert backend.sets == [expected]
        backend.sets.clear()

    if rcode == dns.rcode.NOERROR:
        asyncio.run(exercise(True))
    asyncio.run(exercise(False))


@pytest.mark.parametrize("bundled", [False, True], ids=["separate-address", "glue-address"])
def test_referral_after_cname_uses_origin_policy(
    tmp_path: Path, bundled: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Mock(return_value=100.0)
    monkeypatch.setattr(dns_service, "time", clock)
    backend = FakeBackend()
    matcher = FakeRuleMatcher({"origin.example": 1})
    addr = dns.rrset.from_text("ns.zone.example.", 80, "IN", "A", "192.0.2.5")

    async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        owner = query.question[0].name
        response = dns.message.make_response(query)
        if owner == dns.name.from_text("origin.example."):
            response.answer.append(
                dns.rrset.from_text(owner, 10, "IN", "CNAME", "app.zone.example.")
            )
        elif owner == dns.name.from_text("app.zone.example."):
            response.authority.append(
                dns.rrset.from_text("zone.example.", 60, "IN", "NS", addr.name.to_text())
            )
            if bundled:
                response.additional.append(addr)
        else:
            response.answer.append(addr)
        return dns.message.from_wire(response.to_wire())

    async def ask(name: str, kind: str) -> dns.message.Message:
        service = PolicyDnsService(
            upstream, alias_path=tmp_path / "aliases.db", matcher_factory=lambda: matcher
        )
        service.on_answer(backend.add_to_set)
        wire = await _Stub(service, _plan()).answer(
            dns.message.make_query(name, kind).to_wire(), tcp=True
        )
        return dns.message.from_wire(wire)

    assert asyncio.run(ask("origin.example.", "CNAME")).rcode() == dns.rcode.NOERROR
    clock.return_value += 4
    referral = asyncio.run(ask("app.zone.example.", "SRV"))
    assert referral.rcode() == dns.rcode.NOERROR
    assert referral.authority[0].ttl == 6
    expected = DestSet(1, v4=frozenset({ip_network("192.0.2.5")}))
    assert backend.sets == ([expected] if bundled else [])
    backend.sets.clear()
    assert asyncio.run(ask("ns.zone.example.", "A")).answer[0][0].address == "192.0.2.5"
    assert backend.sets == [expected]


def test_negative_authority_is_not_a_nameserver_referral(tmp_path: Path) -> None:
    addr = dns.rrset.from_text("ns.example.", 60, "IN", "A", "192.0.2.10")
    backend = FakeBackend()

    async def upstream(_: PolicyPlan, query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        if query.question[0].name == addr.name:
            response.answer.append(addr)
        else:
            response.authority.extend(
                [
                    dns.rrset.from_text(
                        "example.", 60, "IN", "SOA", "ns.example. hostmaster.example. 1 2 3 4 5"
                    ),
                    dns.rrset.from_text("example.", 60, "IN", "NS", "ns.example."),
                ]
            )
            response.additional.append(addr)
        return dns.message.from_wire(response.to_wire())

    async def run() -> None:
        service = PolicyDnsService(
            upstream,
            alias_path=tmp_path / "aliases.db",
            matcher_factory=lambda: FakeRuleMatcher({"origin.example": 1}),
        )
        service.on_answer(backend.add_to_set)
        stub = _Stub(service, _plan())
        for name in ["origin.example.", "ns.example."]:
            wire = await stub.answer(dns.message.make_query(name, "A").to_wire(), tcp=False)
            assert dns.message.from_wire(wire).rcode() == dns.rcode.NOERROR
        assert not backend.sets

    asyncio.run(run())
