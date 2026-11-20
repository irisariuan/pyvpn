"""Unix-socket JSON-lines API server (protocol in ``daemon/api.py``)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import socket
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


class ApiServer:
    def __init__(self, path: str | os.PathLike[str], handler: Handler, mode: int = 0o666) -> None:
        self.path = Path(path)
        self._handler = handler
        self._mode = mode
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()  # stale socket from a previous run
        self._server = await asyncio.start_unix_server(
            self._client, path=str(self.path), limit=MAX_LINE
        )
        os.chmod(self.path, self._mode)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = peer_cred(writer.get_extra_info("socket"))
        try:
            while True:
                try:
                    line = await reader.readline()
                except (asyncio.LimitOverrunError, ValueError):
                    writer.write(
                        Response(None, False, error=Error("bad_request", "line too long")).encode()
                    )
                    break
                if not line:
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
