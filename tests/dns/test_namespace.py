"""Exercise the real DNS sockets using only interfaces in throwaway namespaces."""

import asyncio
import os
import shutil
import ssl
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from ipaddress import ip_address
from pathlib import Path

import dns.asyncquery
import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest
from aiohttp import web

from pyvpn.dns.service import PolicyDnsService
from pyvpn.dns.upstream import BoundUpstream
from pyvpn.platform.linux.dns import bound_dns_socket
from pyvpn.services import DnsService
from pyvpn.state import DestSet
from tests.dns._helpers import plan_for_dns
from tests.fakes.backend import FakeBackend
from tests.fakes.rules import FakeRuleMatcher

pytestmark = pytest.mark.integration
_UPSTREAM = "203.0.113.53"
_TLS_NAME = "dns.example"
_ANSWER = "203.0.113.17"
_POLICY = plan_for_dns()
_CASES = (
    ("plain", "udp", "udp.example."),
    ("plain", "tcp", "truncated.example."),
    ("dot", "tcp", "dot.example."),
    ("doh", "udp", "doh.example."),
)


def _ip(*args: str) -> str:
    return subprocess.run(
        ["ip", *args], check=True, capture_output=True, text=True, timeout=10
    ).stdout


def _worker(ns: str, *args: str) -> list[str]:
    return ["ip", "netns", "exec", ns, sys.executable, "-m", "tests.dns.test_namespace", *args]


@contextmanager
def _peer(ns: str, tmp_path: Path, cert: Path, key: Path) -> Iterator[Path]:
    ready = tmp_path / f"{ns}.ready"
    hits = tmp_path / f"{ns}.hits"
    log = tmp_path / f"{ns}.log"
    with (
        log.open("w") as output,
        subprocess.Popen(
            _worker(ns, "peer", str(cert), str(key), str(ready), str(hits)),
            stdout=output,
            stderr=subprocess.STDOUT,
        ) as process,
    ):
        try:
            deadline = time.monotonic() + 10
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert ready.exists(), log.read_text()
            yield hits
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def test_bound_dns_uses_target_and_fails_closed_after_link_loss(tmp_path: Path) -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.skip("requires root in a disposable Linux test environment")
    for tool in ("ip", "openssl"):
        if shutil.which(tool) is None:
            pytest.skip(f"requires {tool}")

    cert, key = tmp_path / "dns.pem", tmp_path / "dns.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            f"/CN={_TLS_NAME}",
            "-addext",
            f"subjectAltName=DNS:{_TLS_NAME}",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    prefix = f"pyvpn-f-{uuid.uuid4().hex[:10]}"
    client, wan, target = (f"{prefix}-{role}" for role in ("client", "wan", "target"))
    with ExitStack() as stack:
        for ns in (client, wan, target):
            _ip("netns", "add", ns)
            stack.callback(_ip, "netns", "delete", ns)
            _ip("-n", ns, "link", "set", "lo", "up")

        for ns, device, subnet, table in (
            (wan, "wan0", "198.51.100", "main"),
            (target, "vpn0", "192.0.2", str(_POLICY.table)),
        ):
            _ip(
                "-n",
                client,
                "link",
                "add",
                device,
                "type",
                "veth",
                "peer",
                "name",
                "edge0",
                "netns",
                ns,
            )
            _ip("-n", ns, "addr", "add", f"{_UPSTREAM}/32", "dev", "lo")
            for side, link, host in ((client, device, "1"), (ns, "edge0", "2")):
                _ip("-n", side, "addr", "add", f"{subnet}.{host}/30", "dev", link)
                _ip("-n", side, "link", "set", link, "up")
            _ip(
                "-n",
                client,
                "route",
                "add",
                "default",
                "via",
                f"{subnet}.2",
                "dev",
                device,
                "table",
                table,
            )

        _ip(
            "-n",
            client,
            "rule",
            "add",
            "pref",
            str(_POLICY.rule_pref),
            "fwmark",
            f"{_POLICY.mark:#x}",
            "lookup",
            str(_POLICY.table),
        )
        assert "dev wan0" in _ip("-n", client, "route", "get", _UPSTREAM)
        assert "dev vpn0" not in _ip("-n", client, "route", "show", "table", "main", "default")
        assert "dev vpn0" in _ip("-n", client, "route", "get", _UPSTREAM, "mark", hex(_POLICY.mark))
        wan_hits = stack.enter_context(_peer(wan, tmp_path, cert, key))
        target_hits = stack.enter_context(_peer(target, tmp_path, cert, key))
        subprocess.run(_worker(client, "client", str(cert), "up"), check=True, timeout=45)
        assert target_hits.read_text().splitlines() == [
            "udp udp.example.",
            "udp truncated.example.",
            "tcp truncated.example.",
            "dot dot.example.",
            "doh doh.example.",
        ]
        assert not wan_hits.exists()

        _ip("-n", client, "link", "delete", "vpn0")
        assert "dev wan0" in _ip("-n", client, "route", "get", _UPSTREAM)
        subprocess.run(_worker(client, "client", str(cert), "down"), check=True, timeout=45)
        assert not wan_hits.exists()


async def _serve_peer(cert: Path, key: Path, ready: Path, hits: Path) -> None:
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)

    def reply(wire: bytes, transport: str) -> bytes:
        query = dns.message.from_wire(wire)
        name = query.question[0].name.to_text()
        with hits.open("a") as output:
            print(transport, name, file=output)
        response = dns.message.make_response(query)
        if transport == "udp" and name == "truncated.example.":
            response.flags |= dns.flags.TC
        else:
            response.answer.append(dns.rrset.from_text(name, 60, "IN", "A", _ANSWER))
        return response.to_wire()

    class UdpPeer(asyncio.DatagramProtocol):
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            self.transport.sendto(reply(data, "udp"), addr)

    async def stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            count = int.from_bytes(await reader.readexactly(2), "big")
            transport = "dot" if writer.get_extra_info("ssl_object") else "tcp"
            wire = reply(await reader.readexactly(count), transport)
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
        finally:
            writer.close()

    async def doh(request: web.Request) -> web.Response:
        return web.Response(
            body=reply(await request.read(), "doh"),
            content_type="application/dns-message",
        )

    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(UdpPeer, local_addr=(_UPSTREAM, 53))
    tcp = await asyncio.start_server(stream, _UPSTREAM, 53)
    dot = await asyncio.start_server(stream, _UPSTREAM, 853, ssl=tls)
    app = web.Application()
    app.router.add_post("/dns-query", doh)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, _UPSTREAM, 443, ssl_context=tls).start()
    ready.touch()
    try:
        await asyncio.Future()
    finally:
        udp.close()
        tcp.close()
        dot.close()
        await runner.cleanup()


async def _probe_client(cert: str, expected: str) -> None:
    upstream = BoundUpstream(bound_dns_socket, tls_context=ssl.create_default_context(cafile=cert))
    backend = FakeBackend()
    matcher = FakeRuleMatcher({name.rstrip("."): 1 for _, _, name in _CASES})
    service: DnsService = PolicyDnsService(
        upstream, alias_path=Path(cert).with_suffix(".sqlite3"), matcher_factory=lambda: matcher
    )
    service.on_answer(backend.add_to_set)
    try:
        for protocol, transport, name in _CASES:
            address = _UPSTREAM if protocol == "plain" else f"{_TLS_NAME}@{_UPSTREAM}"
            plan = replace(
                plan_for_dns(dns_protocol=protocol, dns_server=address),
                interface="vpn0",
                gateway=ip_address("192.0.2.2"),
                dests=DestSet(1),
            )
            await service.start(plan)
            query = dns.message.make_query(name, "A")
            exchange = dns.asyncquery.tcp if transport == "tcp" else dns.asyncquery.udp
            response = await exchange(query, "127.0.0.1", port=5301, timeout=8)
            if expected == "up":
                assert response.rcode() == dns.rcode.NOERROR, response
                assert response.answer[0][0].address == _ANSWER
            else:
                assert response.rcode() == dns.rcode.SERVFAIL, response
                assert not response.answer
        assert len(backend.sets) == (len(_CASES) if expected == "up" else 0)
    finally:
        await service.stop(1)


if __name__ == "__main__":
    if sys.argv[1] == "peer":
        asyncio.run(_serve_peer(*(Path(arg) for arg in sys.argv[2:])))
    else:
        asyncio.run(_probe_client(*sys.argv[2:]))
