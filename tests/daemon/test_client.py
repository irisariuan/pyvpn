import json
import socket
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

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
