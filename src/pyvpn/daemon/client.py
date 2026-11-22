"""Synchronous JSON-lines client for the pyvpn daemon."""

from __future__ import annotations

import json
import math
import socket
from pathlib import Path
from typing import Any, cast

from pyvpn.constants import MAX_POLICIES, SOCKET_PATH
from pyvpn.daemon.api import MAX_LINE, Error, ErrorCode, Request, Response

ERROR_CODES = frozenset(
    {"bad_request", "unknown_method", "not_found", "forbidden", "unavailable", "internal"}
)


def _decode_response_boundary(line: bytes) -> Response:
    """validate the daemon response envelope before using shared dataclasses."""

    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    decoded = json.loads(
        line,
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicate_keys,
    )
    if not isinstance(decoded, dict):
        raise ValueError("daemon response must be a JSON object")
    if set(decoded) - {"id", "ok", "result", "error"}:
        raise ValueError("daemon response contains unknown fields")
    if "id" not in decoded or type(decoded["id"]) is not int:
        raise ValueError("daemon response id must be an integer")
    if "ok" not in decoded or type(decoded["ok"]) is not bool:
        raise ValueError("daemon response ok must be a boolean")

    response_id = decoded["id"]
    ok = decoded["ok"]
    if ok:
        if "error" in decoded or "result" not in decoded:
            raise ValueError("successful daemon response requires result and no error")
        return Response(id=response_id, ok=True, result=decoded["result"])

    if "result" in decoded or "error" not in decoded:
        raise ValueError("error daemon response requires error and no result")
    error = decoded["error"]
    if not isinstance(error, dict) or set(error) != {"code", "message"}:
        raise ValueError("daemon error must contain code and message")
    code = error["code"]
    message = error["message"]
    if code not in ERROR_CODES:
        raise ValueError("daemon error code is invalid")
    if not isinstance(message, str):
        raise ValueError("daemon error message must be a string")
    return Response(
        id=response_id,
        ok=False,
        error=Error(cast(ErrorCode, code), message),
    )


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
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("daemon timeout must be a finite positive number")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("daemon timeout must be a finite positive number")
        self.socket_path = str(socket_path)
        self.timeout = float(timeout)
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
            response = _decode_response_boundary(line)
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
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("pid must be a positive integer")
        if isinstance(policy, bool) or not isinstance(policy, (str, int)):
            raise ValueError("policy must be a non-empty name or policy id")
        if isinstance(policy, int):
            if not 1 <= policy <= MAX_POLICIES:
                raise ValueError(f"policy id must be between 1 and {MAX_POLICIES}")
        elif not policy.strip():
            raise ValueError("policy name must not be empty")
        return self.request("place_pid", {"pid": pid, "policy": policy})

    def disable(self) -> Any:
        return self.request("disable")

    def enable(self) -> Any:
        return self.request("enable")

    def audit(self) -> Any:
        return self.request("audit")
