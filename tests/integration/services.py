"""Internet-side services for the test bed (PLAN.md §8).

Started inside the "internet" namespace by ``Netbed.services()``:

    python -m tests.integration.services serve READY LOG ADDRESS TCP_PORT UDP_PORT DNS_PORT

A TCP echo, a UDP echo and an A-only DNS responder on one address. Each echo
reply carries the client address the server observed (``peer=<ip>``) and the
DNS query's source is recorded the same way, and every observation is appended
to LOG as JSON lines. The client half, run inside the "host" namespace, prints
that evidence: 192.0.2.2 means the packet left over the WAN link, 198.51.100.2
over the VPN link. No tcpdump and no kernel counters.

The responder is deliberately small: it answers A queries with one address,
returns NOERROR/NODATA for other qtypes, never NXDOMAIN, and has no TCP
listener. Protocol coverage (AAAA, HTTPS/SVCB, TCP fallback) belongs to the
DNS suite's own peers (``tests/dns/test_namespace.py``).
"""

from __future__ import annotations

import contextlib
import json
import os
import selectors
import socket
import sys
import time
from pathlib import Path
from typing import TextIO

ANSWER_ADDRESS = "203.0.113.1"  # the service address, reachable over either link


def serve(
    ready: Path,
    log_path: Path,
    address: str,
    tcp_port: int,
    udp_port: int,
    dns_port: int,
) -> int:
    """Echo on TCP and UDP and answer A queries until the parent terminates us."""
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((address, tcp_port))
    tcp.listen(8)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((address, udp_port))
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind((address, dns_port))
    for sock in (tcp, udp, dns):
        sock.setblocking(False)

    selector = selectors.DefaultSelector()
    selector.register(tcp, selectors.EVENT_READ)
    selector.register(udp, selectors.EVENT_READ)
    selector.register(dns, selectors.EVENT_READ)
    ready.write_text(f"{time.time()}\n")
    with log_path.open("a", encoding="utf-8") as log:
        while True:
            for key, _ in selector.select(timeout=1.0):
                if key.fileobj is tcp:
                    _accept(tcp, log)
                elif key.fileobj is udp:
                    _reply_udp(udp, log)
                else:
                    _reply_dns(dns, log)


def _record(log: TextIO, kind: str, peer: str) -> None:
    log.write(json.dumps({"kind": kind, "peer": peer}) + "\n")
    log.flush()


def _accept(listener: socket.socket, log: TextIO) -> None:
    while True:
        try:
            conn, peer = listener.accept()
        except OSError:
            return
        with conn:
            # A client that connects and sends nothing must not stall the
            # loop that also serves UDP and DNS.
            conn.settimeout(0.25)
            _record(log, "tcp", peer[0])
            with contextlib.suppress(OSError):
                conn.recv(64)
            with contextlib.suppress(OSError):
                conn.sendall(f"peer={peer[0]}\n".encode())


def _reply_udp(sock: socket.socket, log: TextIO) -> None:
    while True:
        try:
            _, peer = sock.recvfrom(2048)
        except OSError:
            return
        _record(log, "udp", peer[0])
        with contextlib.suppress(OSError):
            sock.sendto(f"peer={peer[0]}\n".encode(), peer)


def _reply_dns(sock: socket.socket, log: TextIO) -> None:
    while True:
        try:
            packet, peer = sock.recvfrom(2048)
        except BlockingIOError:
            return
        _record(log, "dns", peer[0])
        with contextlib.suppress(ValueError, OSError):
            sock.sendto(_dns_answer(packet), peer)


def _dns_answer(packet: bytes) -> bytes:
    qid, question, offset = _parse_question(packet)
    qtype = int.from_bytes(packet[offset - 4 : offset - 2], "big")
    answers = 1 if qtype == 1 else 0  # A only; everything else is NOERROR/NODATA
    header = (
        qid.to_bytes(2, "big")
        + b"\x81\x80"  # response, recursion available, no error
        + (1).to_bytes(2, "big")  # one question
        + answers.to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
    )
    if not answers:
        return header + question
    answer = b"\xc0\x0c\x00\x01\x00\x01" + (60).to_bytes(4, "big") + b"\x00\x04"
    return header + question + answer + socket.inet_aton(ANSWER_ADDRESS)


def _parse_question(packet: bytes) -> tuple[int, bytes, int]:
    """Return the query id, the question section and the offset after it."""
    if len(packet) < 12:
        raise ValueError("short DNS query")
    offset = 12
    while offset < len(packet) and packet[offset]:
        offset += packet[offset] + 1
    offset += 1
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    return int.from_bytes(packet[:2], "big"), packet[12 : offset + 4], offset + 4


def probe(kind: str, address: str, port: int, timeout: float = 5.0) -> str:
    """Send one echo request and return the peer address the server saw."""
    if kind == "tcp":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((address, port))
            sock.sendall(b"ping\n")
            return _peer(sock.recv(256))
    if kind == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            # Connecting makes the kernel drop datagrams from anyone else.
            sock.connect((address, port))
            sock.send(b"ping")
            return _peer(sock.recv(256))
    raise ValueError(f"unknown probe kind {kind!r}")


def query(name: str, address: str, port: int, timeout: float = 5.0) -> str:
    """Ask for an A record and return the first address in the answer."""
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".") if part)
    request = (
        os.urandom(2)
        + b"\x01\x00"
        + (1).to_bytes(2, "big")
        + b"\x00\x00\x00\x00\x00\x00"
        + labels
        + b"\x00\x00\x01\x00\x01"
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(request, (address, port))
        return _first_a(sock.recv(2048))


def _first_a(packet: bytes) -> str:
    _, _, offset = _parse_question(packet)
    while offset < len(packet):
        if packet[offset] & 0xC0:
            offset += 2
        else:
            while offset < len(packet) and packet[offset]:
                offset += packet[offset] + 1
            offset += 1
        if offset + 10 > len(packet):
            break
        rtype = int.from_bytes(packet[offset : offset + 2], "big")
        rdlen = int.from_bytes(packet[offset + 8 : offset + 10], "big")
        offset += 10
        if rtype == 1 and rdlen == 4:
            return socket.inet_ntoa(packet[offset : offset + 4])
        offset += rdlen
    raise ValueError("the reply has no A record")


def _peer(payload: bytes) -> str:
    text = payload.decode("ascii", errors="replace").strip()
    if not text.startswith("peer="):
        raise ValueError(f"unexpected echo reply {text!r}")
    return text.removeprefix("peer=")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 7 and args[0] == "serve":
        return serve(
            Path(args[1]), Path(args[2]), args[3], int(args[4]), int(args[5]), int(args[6])
        )
    if len(args) in (4, 5) and args[0] == "probe":
        timeout = float(args[4]) if len(args) == 5 else 5.0
        print(probe(args[1], args[2], int(args[3]), timeout))
        return 0
    if len(args) in (3, 4, 5) and args[0] == "query":
        port = int(args[3]) if len(args) >= 4 else 53
        timeout = float(args[4]) if len(args) == 5 else 5.0
        print(query(args[2], args[1], port, timeout))
        return 0
    print(
        "usage: services serve READY LOG ADDRESS TCP_PORT UDP_PORT DNS_PORT | "
        "services probe tcp|udp ADDRESS PORT [TIMEOUT] | "
        "services query ADDRESS NAME [PORT] [TIMEOUT]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
