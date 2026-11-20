"""Unix-socket JSON-lines API server (protocol in ``daemon/api.py``)."""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import logging
import os
import socket
import stat
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pyvpn.daemon.api import MAX_LINE, METHODS, Error, ErrorCode, Response

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PeerCred:
    pid: int
    uid: int
    gid: int


class ApiError(Exception):
    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: ErrorCode = code
        self.message = message


Handler = Callable[[str, dict[str, Any], PeerCred | None], Awaitable[Any]]


def peer_cred(sock: socket.socket | None) -> PeerCred | None:
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if sock is None or so_peercred is None:
        return None
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
    except OSError:
        return None
    pid, uid, gid = struct.unpack("3i", raw)
    return PeerCred(pid, uid, gid)


def acquire_instance_lock(path: Path) -> int:
    """Lock the daemon instance until the caller closes the returned descriptor."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f"{path.name}.lock")
    # Keep this file in place so competing daemons always lock the same inode.
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException as exc:
        os.close(fd)
        if isinstance(exc, BlockingIOError):
            raise RuntimeError(f"another pyvpn daemon owns {path}") from None
        raise
    return fd


class ApiServer:
    def __init__(self, path: str | os.PathLike[str], handler: Handler, mode: int = 0o666) -> None:
        self.path = Path(path)
        self._handler = handler
        self._mode = mode
        self._server: asyncio.Server | None = None
        self._inode: int | None = None
        self._clients: dict[asyncio.Task[None], asyncio.StreamWriter] = {}
        self._closing = False

    async def start(self, *, start_serving: bool = True) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(FileNotFoundError):
            if not stat.S_ISSOCK(self.path.lstat().st_mode):
                raise RuntimeError(f"API socket path is occupied: {self.path}")
            if await _accepts_connections(self.path):
                raise RuntimeError(f"another pyvpn daemon is serving {self.path}")
            self.path.unlink(missing_ok=True)  # stale socket from a previous run
        self._closing = False
        self._server = await asyncio.start_unix_server(
            self._accept, path=str(self.path), limit=MAX_LINE, start_serving=start_serving
        )
        self._inode = self.path.stat().st_ino
        os.chmod(self.path, self._mode)

    async def serve(self) -> None:
        assert self._server is not None
        await self._server.start_serving()

    async def close(self) -> None:
        self._closing = True
        if self._server is not None:
            self._server.close()
            for writer in self._clients.values():
                writer.close()
            await asyncio.gather(*self._clients, return_exceptions=True)
            await self._server.wait_closed()
            self._server = None
        # Remove the socket only if it is still ours, not a successor's.
        with contextlib.suppress(FileNotFoundError):
            if self._inode is not None and self.path.stat().st_ino == self._inode:
                self.path.unlink()
        self._inode = None

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._closing:
            writer.close()
            return
        task = asyncio.create_task(self._client(reader, writer))
        self._clients[task] = writer
        task.add_done_callback(self._clients.pop)

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = peer_cred(writer.get_extra_info("socket"))
        try:
            while not self._closing:
                try:
                    line = await reader.readline()
                except (asyncio.LimitOverrunError, ValueError):
                    writer.write(
                        Response(None, False, error=Error("bad_request", "line too long")).encode()
                    )
                    break
                if not line or self._closing:
                    break
                writer.write((await self._dispatch(line, peer)).encode())
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _dispatch(self, line: bytes, peer: PeerCred | None) -> Response:
        rid: int | None = None
        try:
            try:
                req = json.loads(line)
            except ValueError as e:
                raise ApiError("bad_request", f"invalid JSON: {e}") from None
            if not isinstance(req, dict):
                raise ApiError("bad_request", "request must be an object")
            rid = req.get("id") if isinstance(req.get("id"), int) else None
            method = req.get("method")
            params = req.get("params") or {}
            if not isinstance(method, str) or method not in METHODS:
                raise ApiError("unknown_method", f"unknown method {method!r}")
            if not isinstance(params, dict):
                raise ApiError("bad_request", "params must be an object")
            result = await self._handler(method, params, peer)
            return Response(rid, True, result=result)
        except ApiError as e:
            return Response(rid, False, error=Error(e.code, e.message))
        except Exception as e:
            log.exception("API handler failed")
            return Response(rid, False, error=Error("internal", str(e)))


async def _accepts_connections(path: Path) -> bool:
    """Whether a live server is listening on the unix socket at ``path``."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(path)), 1.0)
    except (FileNotFoundError, ConnectionRefusedError):
        return False
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return True
