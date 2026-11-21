"""Synchronous JSON-lines client for the pyvpn daemon."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from pyvpn.constants import SOCKET_PATH
from pyvpn.daemon.api import MAX_LINE, Error, Request, Response


class DaemonClientError(RuntimeError):
    """base class for daemon client failures."""


class DaemonUnavailable(DaemonClientError):
    """the daemon could not be contacted or returned no complete response."""


class DaemonProtocolError(DaemonClientError):
    """the daemon returned an invalid JSON-lines response."""


class DaemonRequestError(DaemonClientError):
    """the daemon rejected one request."""

    def __init__(self, error: Error) -> None:
        super().__init__(error.message)
        self.error = error


class DaemonClient:
    """send JSON-lines requests over the daemon Unix socket."""

    def __init__(
        self,
        socket_path: str | Path = SOCKET_PATH,
        *,
        timeout: float = 2.0,
    ) -> None:
        self.socket_path = str(socket_path)
        self.timeout = timeout
        self._next_id = 1

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """send one daemon request and return its result."""
        request_id = self._next_id
        self._next_id += 1
        request = Request(request_id, method, params or {})

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as daemon:
                daemon.settimeout(self.timeout)
                daemon.connect(self.socket_path)
                daemon.sendall(request.encode())
                with daemon.makefile("rb") as stream:
                    line = stream.readline(MAX_LINE + 1)
        except (TimeoutError, OSError) as exc:
            raise DaemonUnavailable(f"cannot contact pyvpn daemon: {exc}") from exc

        if not line:
            raise DaemonUnavailable("daemon returned an empty response")
        if len(line) > MAX_LINE:
            raise DaemonUnavailable("daemon returned an oversized response")
        if not line.endswith(b"\n"):
            raise DaemonProtocolError("daemon returned a response without a newline")

        try:
            response = Response.decode(line)
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise DaemonProtocolError("daemon returned an invalid response") from exc

        if response.id != request_id:
            raise DaemonProtocolError(
                f"daemon returned response id {response.id!r}; expected {request_id}"
            )
        if not response.ok:
            error = response.error
            if error is None:
                raise DaemonProtocolError("daemon returned an error without details")
            raise DaemonRequestError(error)
        return response.result

    def status(self) -> Any:
        return self.request("status")

    def apps(self) -> Any:
        return self.request("apps")

    def reload(self) -> Any:
        return self.request("reload")

    def place_pid(self, pid: int, policy: str | int) -> Any:
        return self.request("place_pid", {"pid": pid, "policy": policy})

    def disable(self) -> Any:
        return self.request("disable")

    def audit(self) -> Any:
        return self.request("audit")
