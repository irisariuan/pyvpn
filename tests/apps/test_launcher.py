from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

from pyvpn.apps.launcher import request_place_pid


def test_launcher_sends_place_pid_request(tmp_path: Path) -> None:
    path = tmp_path / "daemon.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
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
    request_place_pid("JP", socket_path=path)
    thread.join(timeout=2)
    assert seen[0]["method"] == "place_pid"
    assert seen[0]["params"]["policy"] == "JP"  # type: ignore[index]
