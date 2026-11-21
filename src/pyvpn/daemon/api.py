"""Daemon API (Phase 0 contract): JSON lines over the unix socket.

Each request and response is one JSON object on one line (UTF-8, ``\\n``).

Request:  {"id": 1, "method": "status", "params": {}}
Response: {"id": 1, "ok": true, "result": {...}}
          {"id": 1, "ok": false, "error": {"code": "bad_request", "message": "..."}}
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Final, Literal, TypeAlias

Method: TypeAlias = Literal["status", "apps", "reload", "place_pid", "disable", "enable", "audit"]
METHODS: Final[frozenset[str]] = frozenset(
    {"status", "apps", "reload", "place_pid", "disable", "enable", "audit"}
)

ErrorCode: TypeAlias = Literal[
    "bad_request", "unknown_method", "not_found", "forbidden", "unavailable", "internal"
]

MAX_LINE: Final = 64 * 1024


@dataclass(frozen=True)
class Request:
    id: int
    method: str
    params: dict[str, Any] = field(default_factory=dict)

    def encode(self) -> bytes:
        return (json.dumps(asdict(self), separators=(",", ":")) + "\n").encode()


@dataclass(frozen=True)
class Error:
    code: ErrorCode
    message: str


@dataclass(frozen=True)
class Response:
    id: int | None
    ok: bool
    result: Any = None
    error: Error | None = None

    def encode(self) -> bytes:
        d: dict[str, Any] = {"id": self.id, "ok": self.ok}
        if self.ok:
            d["result"] = self.result
        else:
            d["error"] = asdict(self.error) if self.error else None
        return (json.dumps(d, separators=(",", ":")) + "\n").encode()

    @classmethod
    def decode(cls, line: bytes) -> Response:
        d = json.loads(line)
        err = d.get("error")
        return cls(
            id=d.get("id"),
            ok=bool(d["ok"]),
            result=d.get("result"),
            error=Error(err["code"], err["message"]) if err else None,
        )


# --- params / results -------------------------------------------------------


@dataclass(frozen=True)
class PlacePidParams:
    """``pyvpn run``: put ``pid`` into a policy (by name or id).

    Unprivileged callers may only place their own PID.
    """

    pid: int
    policy: str | int


@dataclass(frozen=True)
class PolicyStatus:
    id: int
    name: str
    route: str  # "dev" | "unreachable" | "main"
    target: str | None
    interface: str | None
    on_down: str


@dataclass(frozen=True)
class StatusResult:
    enabled: bool
    policies: list[PolicyStatus]
    targets: dict[str, dict[str, Any]]
    last_error: str | None = None


@dataclass(frozen=True)
class AppsEntry:
    policy_id: int
    policy: str
    cgroup_paths: list[str]
    uids: list[int]
    any_process: bool
