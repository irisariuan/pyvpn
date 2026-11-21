import json
import socket
import threading
from pathlib import Path

import pytest

from pyvpn.cli import main

VALID_CONFIG = """
{
  "version": 1,
  "targets": [{"name": "jp", "interface": "wg-jp"}],
  "policies": [{"name": "Japan", "targets": ["jp"], "apps": [{"name": "firefox"}]}]
}
"""


def fake_daemon(
    path: Path,
    response: dict[str, object],
) -> threading.Thread:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            conn.makefile("rb").readline()
            conn.sendall((json.dumps(response, separators=(",", ":")) + "\n").encode())
        server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    return thread


def join(thread: threading.Thread) -> None:
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_status_human_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(
        path,
        {
            "id": 1,
            "ok": True,
            "result": {
                "enabled": True,
                "policies": [
                    {
                        "id": 1,
                        "name": "Japan",
                        "route": "dev",
                        "target": "jp",
                        "interface": "wg-jp",
                    }
                ],
            },
        },
    )

    assert main(["--socket", str(path), "status"]) == 0
    join(thread)
    assert "daemon: enabled" in capsys.readouterr().out


def test_status_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(
        path,
        {"id": 1, "ok": True, "result": {"enabled": False, "policies": []}},
    )

    assert main(["--json", "--socket", str(path), "status"]) == 0
    join(thread)
    assert json.loads(capsys.readouterr().out)["enabled"] is False


def test_apps_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(
        path,
        {
            "id": 1,
            "ok": True,
            "result": [
                {"policy_id": 1, "policy": "Japan", "cgroup_paths": ["p-1"], "uids": [1000]}
            ],
        },
    )

    assert main(["--json", "--socket", str(path), "apps"]) == 0
    join(thread)
    assert json.loads(capsys.readouterr().out)[0]["policy"] == "Japan"


def test_apps_human_output_empty(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(path, {"id": 1, "ok": True, "result": []})

    assert main(["--socket", str(path), "apps"]) == 0
    join(thread)
    assert "no active app bindings" in capsys.readouterr().out


def test_policy_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "config.json"
    path.write_text(VALID_CONFIG, encoding="utf-8")

    assert main(["--json", "policy", "--config", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["policies"][0]["name"] == "Japan"


def test_policy_unknown_name(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "config.json"
    path.write_text(VALID_CONFIG, encoding="utf-8")

    assert main(["policy", "Missing", "--config", str(path)]) == 1
    assert "policy not found: Missing" in capsys.readouterr().err


def test_test_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "config.json"
    path.write_text(VALID_CONFIG, encoding="utf-8")

    assert main(["test", str(path)]) == 0
    assert "ok" in capsys.readouterr().out


def test_test_config_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "config.json"
    path.write_text(VALID_CONFIG, encoding="utf-8")

    assert main(["--json", "test", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_daemon_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--socket", str(tmp_path / "missing.sock"), "status"]) == 1
    assert "cannot contact" in capsys.readouterr().err


def test_reload_human_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(
        path,
        {"id": 1, "ok": True, "result": {"message": "configuration reloaded"}},
    )

    assert main(["--socket", str(path), "reload"]) == 0
    join(thread)
    assert "configuration reloaded" in capsys.readouterr().out


def test_reload_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(path, {"id": 1, "ok": True, "result": {"reloaded": True}})

    assert main(["--json", "--socket", str(path), "reload"]) == 0
    join(thread)
    assert json.loads(capsys.readouterr().out) == {"reloaded": True}


def test_disable_human_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(path, {"id": 1, "ok": True, "result": None})

    assert main(["--socket", str(path), "disable"]) == 0
    join(thread)
    assert "disable: ok" in capsys.readouterr().out


def test_disable_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(path, {"id": 1, "ok": True, "result": {"disabled": True}})

    assert main(["--json", "--socket", str(path), "disable"]) == 0
    join(thread)
    assert json.loads(capsys.readouterr().out) == {"disabled": True}


def test_audit_human_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(
        path,
        {
            "id": 1,
            "ok": True,
            "result": {"enabled": True, "policies": [{"name": "Japan"}]},
        },
    )

    assert main(["--socket", str(path), "audit"]) == 0
    join(thread)
    output = capsys.readouterr().out
    assert "enabled: yes" in output
    assert "policies: 1" in output


def test_audit_human_output_includes_list_and_dict_findings(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(
        path,
        {
            "id": 1,
            "ok": True,
            "result": {
                "enabled": True,
                "policies": [{"name": "Japan"}],
                "issues": ["IPv6 leak", "competing rule"],
                "dns": {"stub": "ok", "interface": "wg-jp"},
            },
        },
    )

    assert main(["--socket", str(path), "audit"]) == 0
    join(thread)
    output = capsys.readouterr().out
    assert "issues:" in output
    assert "  - IPv6 leak" in output
    assert "  - competing rule" in output
    assert "dns:" in output
    assert "  stub: ok" in output


def test_audit_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(
        path,
        {"id": 1, "ok": True, "result": {"enabled": False, "issues": ["IPv6 leak"]}},
    )

    assert main(["--json", "--socket", str(path), "audit"]) == 0
    join(thread)
    assert json.loads(capsys.readouterr().out)["enabled"] is False
