import asyncio
import socket
import sys
from dataclasses import replace
from ipaddress import ip_address
from unittest.mock import AsyncMock, MagicMock, Mock, call

import aiohttp
import dns.flags
import dns.message
import pytest

from pyvpn.dns.upstream import BoundUpstream, upstream_endpoint
from pyvpn.platform.linux.dns import bound_dns_socket
from tests.dns._helpers import plan_for_dns as _plan


def test_endpoint_requires_numeric_address_and_accepts_explicit_tls_name() -> None:
    assert upstream_endpoint("dns.example@2001:db8::53", "doh") == (
        ip_address("2001:db8::53"),
        "dns.example",
    )
    assert upstream_endpoint("192.0.2.53", "plain") == (ip_address("192.0.2.53"), "192.0.2.53")
    with pytest.raises(ValueError):
        upstream_endpoint("dns.example", "dot")
    with pytest.raises(ValueError):
        upstream_endpoint("dns.example@192.0.2.53", "plain")
    with pytest.raises(ValueError, match="remote unicast"):
        upstream_endpoint("::ffff:127.0.0.53", "plain")


def test_failed_binding_closes_socket_without_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = Mock()
    sock.setsockopt.side_effect = OSError("interface disappeared")
    monkeypatch.setattr(socket, "SO_BINDTODEVICE", 25, raising=False)
    monkeypatch.setattr(socket, "SO_MARK", 36, raising=False)
    monkeypatch.setattr(socket, "socket", Mock(return_value=sock))

    with pytest.raises(OSError, match="interface disappeared"):
        bound_dns_socket("wg-jp", _plan().mark, socket.AF_INET, socket.SOCK_DGRAM)

    sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET, 25, b"wg-jp\0")
    sock.close.assert_called_once()
    sock.connect.assert_not_called()


def test_failed_route_mark_closes_socket_without_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sock = Mock()
    sock.setsockopt.side_effect = [None, PermissionError("mark denied")]
    monkeypatch.setattr(socket, "SO_BINDTODEVICE", 25, raising=False)
    monkeypatch.setattr(socket, "SO_MARK", 36, raising=False)
    monkeypatch.setattr(socket, "socket", Mock(return_value=sock))
    mark = _plan().mark

    with pytest.raises(PermissionError, match="mark denied"):
        bound_dns_socket("wg-jp", mark, socket.AF_INET, socket.SOCK_DGRAM)

    assert sock.setsockopt.call_args_list == [
        call(socket.SOL_SOCKET, 25, b"wg-jp\0"),
        call(socket.SOL_SOCKET, 36, mark),
    ]
    sock.close.assert_called_once()
    sock.connect.assert_not_called()


def test_missing_dns_server_defaults_to_quad9_on_policy_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    query = dns.message.make_query("example.", "A")
    client = BoundUpstream(bound_dns_socket)
    udp = AsyncMock(return_value=dns.message.make_response(query).to_wire())
    monkeypatch.setattr(client, "_udp", udp)
    plan = _plan(dns_server=None)

    assert query.is_response(asyncio.run(client(plan, query)))
    udp.assert_awaited_once_with("wg-jp", plan.mark, ip_address("9.9.9.9"), query.to_wire())
    assert upstream_endpoint(None, "dot") == (ip_address("9.9.9.9"), "dns.quad9.net")
    assert upstream_endpoint(None, "doh") == (ip_address("9.9.9.9"), "dns.quad9.net")


def test_doh_requires_its_install_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "aiohttp", None)
    query = dns.message.make_query("example.", "A")
    client = BoundUpstream(bound_dns_socket)

    with pytest.raises(RuntimeError, match=r"snakevpn\[doh\]"):
        asyncio.run(client(_plan(dns_protocol="doh"), query))


def test_udp_binds_before_connecting_to_a_numeric_peer(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        sock = MagicMock()
        sock.__enter__.return_value = sock
        calls = Mock()
        calls.bind.return_value = sock
        calls.connect = AsyncMock()
        calls.send = AsyncMock()
        calls.receive = AsyncMock(return_value=b"response")
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "sock_connect", calls.connect)
        monkeypatch.setattr(loop, "sock_sendall", calls.send)
        monkeypatch.setattr(loop, "sock_recv", calls.receive)

        address = ip_address("192.0.2.53")
        mark = _plan().mark
        client = BoundUpstream(calls.bind)
        assert await client._udp("wg-jp", mark, address, b"query") == b"response"
        assert [call[0] for call in calls.method_calls] == ["bind", "connect", "send", "receive"]
        calls.bind.assert_called_once_with("wg-jp", mark, socket.AF_INET, socket.SOCK_DGRAM, 0)
        calls.connect.assert_awaited_once_with(sock, ("192.0.2.53", 53))
        calls.send.assert_awaited_once_with(sock, b"query")

    asyncio.run(run())


def test_plain_truncation_retries_tcp_on_same_target(monkeypatch: pytest.MonkeyPatch) -> None:
    query = dns.message.make_query("example.", "A")
    full = dns.message.make_response(query)
    truncated = dns.message.make_response(query)
    truncated.flags |= dns.flags.TC
    client = BoundUpstream(bound_dns_socket)
    udp = AsyncMock(return_value=truncated.to_wire())
    tcp = AsyncMock(return_value=full.to_wire())
    monkeypatch.setattr(client, "_udp", udp)
    monkeypatch.setattr(client, "_stream", tcp)

    plan = _plan()
    response = asyncio.run(client(plan, query))

    assert query.is_response(response)
    udp.assert_awaited_once_with("wg-jp", plan.mark, ip_address("192.0.2.53"), query.to_wire())
    tcp.assert_awaited_once_with("wg-jp", plan.mark, ip_address("192.0.2.53"), 53, query.to_wire())


def test_dot_uses_bound_stream_and_configured_tls_name(monkeypatch: pytest.MonkeyPatch) -> None:
    query = dns.message.make_query("example.", "A")
    response = dns.message.make_response(query)
    client = BoundUpstream(bound_dns_socket)
    stream = AsyncMock(return_value=response.to_wire())
    monkeypatch.setattr(client, "_stream", stream)
    plan = _plan(dns_protocol="dot", dns_server="dns.example@192.0.2.53")

    assert query.is_response(asyncio.run(client(plan, query)))
    stream.assert_awaited_once_with(
        "wg-jp", plan.mark, ip_address("192.0.2.53"), 853, query.to_wire(), tls_name="dns.example"
    )


def test_doh_pins_address_uses_bound_socket_and_disallows_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def chunks(_: int):
        yield response_wire

    query = dns.message.make_query("example.", "A")
    response_wire = dns.message.make_response(query).to_wire()
    response = Mock(
        status=200,
        content_type="application/dns-message",
        headers={},
        content=Mock(iter_chunked=chunks),
    )
    session = MagicMock()
    session.close = AsyncMock()
    session.post.return_value.__aenter__.return_value = response
    session_factory = Mock(return_value=session)
    connector = Mock()
    binder = Mock()
    monkeypatch.setattr(aiohttp, "ClientSession", session_factory)
    monkeypatch.setattr(aiohttp, "TCPConnector", connector)
    plan = _plan(dns_protocol="doh", dns_server="dns.example@2001:db8::53")

    async def run() -> None:
        client = BoundUpstream(binder)
        assert query.is_response(await client(plan, query))
        assert query.is_response(await client(plan, query))
        await client.close_policy(plan.policy_id)

    asyncio.run(run())
    session_factory.assert_called_once()
    session.close.assert_awaited_once()
    assert session_factory.call_args.kwargs["trust_env"] is False
    expected = call(
        "https://[2001:db8::53]/dns-query",
        data=query.to_wire(),
        headers={
            "Accept": "application/dns-message",
            "Accept-Encoding": "identity",
            "Content-Type": "application/dns-message",
            "Host": "dns.example",
        },
        server_hostname="dns.example",
        allow_redirects=False,
        proxy=None,
    )
    assert session.post.call_args_list == [expected, expected]
    socket_factory = connector.call_args.kwargs["socket_factory"]
    socket_factory((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ()))
    binder.assert_called_once_with(
        "wg-jp", plan.mark, socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP
    )


def test_doh_rejects_unexpected_content_encoding_before_reading_the_body() -> None:
    response = Mock(
        status=200,
        content_type="application/dns-message",
        headers={"Content-Encoding": "gzip"},
    )
    session = MagicMock()
    session.post.return_value.__aenter__.return_value = response
    address = ip_address("192.0.2.53")

    with pytest.raises(ValueError, match="unexpected DoH content encoding"):
        asyncio.run(BoundUpstream(Mock())._https(session, address, str(address), b"query"))

    response.content.iter_chunked.assert_not_called()


def test_inactive_plan_cannot_open_an_upstream_socket() -> None:
    query = dns.message.make_query("example.", "A")
    binder = Mock()
    plan = replace(_plan(), route="main")

    with pytest.raises(ValueError, match="active target"):
        asyncio.run(BoundUpstream(binder)(plan, query))
    binder.assert_not_called()
