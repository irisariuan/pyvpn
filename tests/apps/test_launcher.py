from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

from pyvpn.apps.launcher import request_place_pid


def test_launcher_sends_place_pid_request(daemon_socket_path: Path) -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(daemon_socket_path))
    server.listen(1)
    seen: list[dict[str, object]] = []

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            line = conn.makefile("rb").readline()
            seen.append(json.loads(line))
            conn.sendall(b'{"id":1,"ok":true,"result":{}}\n')
        server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    request_place_pid("JP", socket_path=daemon_socket_path)
    thread.join(timeout=2)
    assert seen[0]["method"] == "place_pid"
    assert seen[0]["params"]["policy"] == "JP"  # type: ignore[index]


def _serve(path: Path, replies: dict[str, object], seen: list[dict[str, Any]]) -> threading.Thread:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(4)

    def serve() -> None:
        with server:
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return
                with conn:
                    stream = conn.makefile("rb")
                    while line := stream.readline():
                        request = json.loads(line)
                        seen.append(request)
                        reply = replies[request["method"]]
                        if isinstance(reply, Exception):
                            body = {
                                "id": request["id"],
                                "ok": False,
                                "error": {"code": "bad_request", "message": str(reply)},
                            }
                        else:
                            body = {"id": request["id"], "ok": True, "result": reply}
                        conn.sendall(json.dumps(body).encode() + b"\n")
                if request["method"] in ("wait_isolated", "place_pid"):
                    return

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def test_auto_isolation_runs_netns_policies_through_the_daemon(
    daemon_socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pyvpn.apps import launcher

    child = subprocess.Popen(["sleep", "5"])
    seen: list[dict[str, Any]] = []
    status = {"policies": [{"id": 2, "name": "Torrents", "isolation": "netns"}]}
    replies = {
        "status": status,
        "run_isolated": {"pid": child.pid, "policy_id": 2},
        "wait_isolated": {"returncode": -2},
    }
    thread = _serve(daemon_socket_path, replies, seen)
    monkeypatch.setattr(launcher.os, "execvp", lambda *a: pytest.fail("must not exec"))
    try:
        code = launcher.run("Torrents", ["qbittorrent", "-x"], socket_path=daemon_socket_path)
    finally:
        child.kill()
        child.wait()
    thread.join(timeout=2)
    assert code == 130  # 128 + SIGINT
    assert [r["method"] for r in seen] == ["status", "run_isolated", "wait_isolated"]
    params = seen[1]["params"]
    assert params["policy"] == "Torrents"
    assert params["argv"] == ["qbittorrent", "-x"]
    assert params["cwd"] == os.getcwd()
    assert params["env"] == dict(os.environ)
    assert seen[2]["params"] == {"pid": child.pid}


def test_auto_isolation_places_ordinary_policies(
    daemon_socket_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pyvpn.apps import launcher

    seen: list[dict[str, Any]] = []
    replies = {
        "status": {"policies": [{"id": 1, "name": "Japan", "isolation": "none"}]},
        "place_pid": {"policy_id": 1},
    }
    thread = _serve(daemon_socket_path, replies, seen)
    execs: list[list[str]] = []

    def fake_exec(file: str, args: list[str]) -> None:
        execs.append(args)
        raise SystemExit(0)

    monkeypatch.setattr(launcher.os, "execvp", fake_exec)
    with pytest.raises(SystemExit):
        launcher.run(1, ["firefox"], socket_path=daemon_socket_path)
    thread.join(timeout=2)
    assert [r["method"] for r in seen] == ["status", "place_pid"]
    assert execs == [["firefox"]]


def test_isolated_run_reports_a_daemon_refusal(daemon_socket_path: Path) -> None:
    from pyvpn.apps import launcher

    seen: list[dict[str, Any]] = []
    replies: dict[str, object] = {"run_isolated": RuntimeError("namespace is not installed yet")}
    _serve(daemon_socket_path, replies, seen)
    with pytest.raises(launcher.DaemonUnavailable, match="not installed"):
        launcher.run("Torrents", ["true"], socket_path=daemon_socket_path, isolation="netns")


def test_unknown_policy_is_reported(daemon_socket_path: Path) -> None:
    from pyvpn.apps import launcher

    _serve(daemon_socket_path, {"status": {"policies": []}}, [])
    with pytest.raises(launcher.DaemonUnavailable, match="no policy"):
        launcher.run("Nope", ["true"], socket_path=daemon_socket_path)
