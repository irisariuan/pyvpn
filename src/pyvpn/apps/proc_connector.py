"""Linux proc-connector subscription for PROC_EVENT_EXEC notifications."""

from __future__ import annotations

import asyncio
import os
import socket
import struct
from collections.abc import AsyncIterator

# Linux netlink connector constants and message layout.
_NETLINK_CONNECTOR = 11
_NLMSG_DONE = 3
_NLMSG_ERROR = 2
_NLM_F_REQUEST = 1
_CN_IDX_PROC = 1
_CN_VAL_PROC = 1
_PROC_CN_MCAST_LISTEN = 1
_PROC_EVENT_EXEC = 0x00000002

# AF_NETLINK only exists on Linux; keep the module importable and type-checkable
# on other hosts so the platform layer can be selected at runtime.
_AF_NETLINK: int | None = getattr(socket, "AF_NETLINK", None)


def _listen_message() -> bytes:
    # nlmsghdr + cn_msg + proc_cn_mcast_op
    payload = struct.pack("=IIIIHH", _CN_IDX_PROC, _CN_VAL_PROC, 0, 0, 4, 0)
    payload += struct.pack("=I", _PROC_CN_MCAST_LISTEN)
    length = 16 + len(payload)
    return struct.pack("=IHHII", length, _NLMSG_DONE, _NLM_F_REQUEST, 1, 0) + payload


def _exec_pid(datagram: bytes) -> int | None:
    """Extract the exec event's tgid from a netlink connector datagram."""
    offset = 0
    while offset + 16 <= len(datagram):
        length, kind, _flags, _seq, _pid = struct.unpack_from("=IHHII", datagram, offset)
        if length < 16 or offset + length > len(datagram):
            return None
        if kind == _NLMSG_ERROR:
            raise OSError("proc connector reported a netlink error")
        # connector header: idx, val, seq, ack, len, flags; event header:
        # what, cpu, timestamp. EXEC data starts with process pid, tgid.
        start = offset + 16
        if length >= 16 + 20 + 16 + 8:
            what = struct.unpack_from("=I", datagram, start + 20)[0]
            if what == _PROC_EVENT_EXEC:
                return int(struct.unpack_from("=I", datagram, start + 20 + 16 + 4)[0])
        offset += (length + 3) & ~3
    return None


class ProcExecEvents:
    """A live PROC_EVENT_EXEC subscription.

    The netlink socket is subscribed when ``open()`` returns, so the kernel
    queues exec events from that moment on, even before iteration starts.
    """

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    @classmethod
    async def open(cls) -> ProcExecEvents:
        """Subscribe to exec events. Requires Linux proc-connector access."""
        if _AF_NETLINK is None:
            raise OSError("proc connector requires Linux (AF_NETLINK)")
        sock = socket.socket(_AF_NETLINK, socket.SOCK_DGRAM, _NETLINK_CONNECTOR)
        try:
            sock.setblocking(False)
            sock.bind((os.getpid(), _CN_IDX_PROC))
            await asyncio.get_running_loop().sock_sendall(sock, _listen_message())
        except BaseException:
            sock.close()
            raise
        return cls(sock)

    async def __aiter__(self) -> AsyncIterator[int]:
        loop = asyncio.get_running_loop()
        while True:
            data = await loop.sock_recv(self._sock, 65536)
            pid = _exec_pid(data)
            if pid is not None:
                yield pid

    def close(self) -> None:
        self._sock.close()
