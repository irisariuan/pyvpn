import json
import socket
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from pyvpn.constants import MAX_POLICIES
from pyvpn.daemon.client import (
    DaemonClient,
    DaemonProtocolError,
    DaemonRequestError,
    DaemonUnavailable,
)


def serve_one(
    path: Path,
    response: bytes,
    seen: list[dict[str, object]],
) -> threading.Thread:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            line = conn.makefile("rb").readline()
            seen.append(json.loads(line))
            conn.sendall(response)
        server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    return thread


def join(thread: threading.Thread) -> None:
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_status_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "daemon.sock"
    seen: list[dict[str, object]] = []
    thread = serve_one(
        path,
        b'{"id":1,"ok":true,"result":{"enabled":true,"policies":[]}}\n',
        seen,
    )

    result = DaemonClient(path).status()

    join(thread)
    assert result == {"enabled": True, "policies": []}
    assert seen[0]["method"] == "status"
    assert seen[0]["params"] == {}


def test_request_rejects_daemon_error(tmp_path: Path) -> None:
    path = tmp_path / "daemon.sock"
    seen: list[dict[str, object]] = []
    thread = serve_one(
        path,
        b'{"id":1,"ok":false,"error":{"code":"not_found","message":"missing policy"}}\n',
        seen,
    )

    with pytest.raises(DaemonRequestError, match="missing policy") as exc:
        DaemonClient(path).place_pid(123, "missing")

    join(thread)
    assert exc.value.error.code == "not_found"


def test_request_rejects_wrong_response_id(tmp_path: Path) -> None:
    path = tmp_path / "daemon.sock"
    seen: list[dict[str, object]] = []
    thread = serve_one(path, b'{"id":99,"ok":true,"result":null}\n', seen)

    with pytest.raises(DaemonProtocolError, match="expected 1"):
        DaemonClient(path).apps()

    join(thread)


@pytest.mark.parametrize(
    "response",
    [
        b"not-json\n",
        b'{"id":1,"ok":true,"result":null}',
        b'{"ok":true,"result":null}\n',
        b'{"id":1,"ok":"false","error":{"code":"not_found","message":"missing"}}\n',
        b'{"id":1,"ok":false,"error":{"code":"bad","message":"missing"}}\n',
        b'{"id":1,"ok":true,"error":{"code":"bad_request","message":"bad"}}\n',
        b'{"id":1,"ok":false,"result":null,"error":{"code":"not_found","message":"missing"}}\n',
        b'{"id":1,"ok":false,"error":{"code":"not_found","message":"missing","extra":true}}\n',
        b'{"id":1,"ok":true,"result":NaN}\n',
        b'{"id":1,"id":99,"ok":true,"result":null}\n',
        b'{"id":1,"ok":false,"error":{"code":"not_found","code":"bad_request","message":"missing"}}\n',
    ],
)
def test_request_rejects_invalid_response(tmp_path: Path, response: bytes) -> None:
    path = tmp_path / "daemon.sock"
    seen: list[dict[str, object]] = []
    thread = serve_one(path, response, seen)

    with pytest.raises(DaemonProtocolError):
        DaemonClient(path).status()

    join(thread)


def test_request_reports_empty_response(tmp_path: Path) -> None:
    path = tmp_path / "daemon.sock"
    seen: list[dict[str, object]] = []
    thread = serve_one(path, b"", seen)

    with pytest.raises(DaemonUnavailable, match="empty response"):
        DaemonClient(path).status()

    join(thread)


def test_request_reports_missing_socket(tmp_path: Path) -> None:
    with pytest.raises(DaemonUnavailable, match="cannot contact"):
        DaemonClient(tmp_path / "missing.sock").status()


@pytest.mark.parametrize(
    ("method", "call", "expected_method"),
    [
        ("status", lambda client: client.status(), "status"),
        ("apps", lambda client: client.apps(), "apps"),
        ("reload", lambda client: client.reload(), "reload"),
        ("disable", lambda client: client.disable(), "disable"),
        ("audit", lambda client: client.audit(), "audit"),
    ],
)
def test_convenience_methods(
    tmp_path: Path,
    method: str,
    call: Callable[[DaemonClient], object],
    expected_method: str,
) -> None:
    path = tmp_path / f"{method}.sock"
    seen: list[dict[str, object]] = []
    thread = serve_one(path, b'{"id":1,"ok":true,"result":{}}\n', seen)

    assert call(DaemonClient(path)) == {}

    join(thread)
    assert seen[0]["method"] == expected_method


def test_place_pid_params(tmp_path: Path) -> None:
    path = tmp_path / "daemon.sock"
    seen: list[dict[str, object]] = []
    thread = serve_one(path, b'{"id":1,"ok":true,"result":null}\n', seen)

    assert DaemonClient(path).place_pid(123, "Japan") is None

    join(thread)
    assert seen[0]["params"] == {"pid": 123, "policy": "Japan"}


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True])
def test_daemon_client_rejects_invalid_timeout(tmp_path: Path, timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        DaemonClient(tmp_path / "daemon.sock", timeout=timeout)


@pytest.mark.parametrize("pid", [0, -1, True])
def test_place_pid_rejects_invalid_pid(pid: int) -> None:
    with pytest.raises(ValueError, match="pid"):
        DaemonClient().place_pid(pid, "Japan")


@pytest.mark.parametrize(
    "policy",
    ["", "   ", True, 1.5, [], {}, None],
)
def test_place_pid_rejects_invalid_policy(policy: object) -> None:
    with pytest.raises(ValueError, match="policy"):
        DaemonClient().place_pid(123, policy)


@pytest.mark.parametrize("policy", [0, -1, MAX_POLICIES + 1])
def test_place_pid_rejects_out_of_range_ids(policy: int) -> None:
    with pytest.raises(ValueError, match=f"between 1 and {MAX_POLICIES}"):
        DaemonClient().place_pid(123, policy)


def test_place_pid_accepts_the_last_policy_id() -> None:
    # Validation passes, so the request is attempted and fails on the socket.
    with pytest.raises(DaemonUnavailable):
        DaemonClient(Path("/nonexistent/pyvpn.sock")).place_pid(123, MAX_POLICIES)
