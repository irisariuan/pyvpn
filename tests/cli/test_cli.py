import json
import socket
import threading
from pathlib import Path

import pytest

from pyvpn.cli import main
from pyvpn.cli.output import format_audit, format_status, print_json
from pyvpn.constants import SOCKET_PATH

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


def test_status_formatter_rejects_malformed_policies() -> None:
    output = format_status({"enabled": True, "policies": "Japan"})
    assert "policies must be a list" in output


def test_status_human_output_preserves_malformed_result(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(path, {"id": 1, "ok": True, "result": "bad-status"})

    assert main(["--socket", str(path), "status"]) == 0
    join(thread)
    assert "malformed daemon status" in capsys.readouterr().out


def test_audit_formatter_rejects_malformed_policies() -> None:
    output = format_audit({"enabled": True, "policies": "Japan"})
    assert "policies: malformed" in output


def test_print_json_rejects_nan() -> None:
    import io

    stream = io.StringIO()
    with pytest.raises(ValueError, match="Out of range"):
        print_json({"value": float("nan")}, stream)


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


def test_apps_human_output_marks_malformed_fields() -> None:
    from pyvpn.cli.output import format_apps

    output = format_apps(
        [
            {
                "policy": "Japan",
                "cgroup_paths": ["pyvpn.slice/p-1", None],
                "uids": [1000, "2000"],
            }
        ]
    )
    assert "Japan: cgroups=malformed; uids=malformed" in output


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


def test_test_reports_unenforceable_exclusions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        '{"targets":[{"name":"jp","interface":"tun0"}],'
        '"policies":[{"name":"Corp","targets":["jp"],"domains":["cidr:203.0.113.0/24"],'
        '"exclude_apps":[{"exe":"/usr/sbin/openvpn"},{"uid":997}]}]}',
        encoding="utf-8",
    )

    assert main(["test", str(path)]) == 1
    out = capsys.readouterr().out
    assert "policy 'Corp': error: exclude_apps exe: '/usr/sbin/openvpn'" in out
    assert "uid" not in out.split("error:")[1].split("\n")[0].split("exe")[0]
    assert out.rstrip().endswith("errors found")


def test_test_warns_about_app_policy_exclusions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        '{"targets":[{"name":"jp","interface":"tun0"}],'
        '"policies":[{"name":"All","targets":["jp"],"apps":[{"uid":1000}],'
        '"exclude_apps":[{"name":"steam"}]}]}',
        encoding="utf-8",
    )

    assert main(["test", str(path)]) == 0
    out = capsys.readouterr().out
    assert "policy 'All': warning: exclude_apps only keep matching processes" in out
    assert out.rstrip().endswith("ok")


def test_daemon_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--socket", str(tmp_path / "missing.sock"), "status"]) == 1
    assert "cannot contact" in capsys.readouterr().err


def test_run_wires_stream_e_launcher(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, list[str], object, object]] = []

    def fake_run(
        policy: str | int,
        command: list[str],
        *,
        socket_path: object,
        isolation: str,
    ) -> None:
        calls.append((policy, command, socket_path, isolation))

    monkeypatch.setattr("pyvpn.cli.run_app", fake_run)

    assert (
        main(
            [
                "run",
                "-p",
                "Japan",
                "--socket",
                "/tmp/test.sock",
                "--",
                "firefox",
                "--private",
            ]
        )
        == 0
    )
    assert calls == [("Japan", ["firefox", "--private"], "/tmp/test.sock", "none")]


def test_run_uses_the_top_level_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[object] = []

    def fake_run(
        policy: str | int, command: list[str], *, socket_path: object, isolation: str
    ) -> None:
        seen.append(socket_path)

    monkeypatch.setattr("pyvpn.cli.run_app", fake_run)

    assert main(["--socket", "/tmp/top.sock", "run", "-p", "Japan", "--", "true"]) == 0
    assert seen == ["/tmp/top.sock"]


def test_run_subcommand_socket_overrides_the_top_level_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[object] = []

    def fake_run(
        policy: str | int, command: list[str], *, socket_path: object, isolation: str
    ) -> None:
        seen.append(socket_path)

    monkeypatch.setattr("pyvpn.cli.run_app", fake_run)

    argv = [
        "--socket",
        "/tmp/top.sock",
        "run",
        "-p",
        "Japan",
        "--socket",
        "/tmp/run.sock",
        "--",
        "true",
    ]
    assert main(argv) == 0
    assert seen == ["/tmp/run.sock"]


def test_run_without_socket_uses_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[object] = []

    def fake_run(
        policy: str | int, command: list[str], *, socket_path: object, isolation: str
    ) -> None:
        seen.append(socket_path)

    monkeypatch.setattr("pyvpn.cli.run_app", fake_run)

    assert main(["run", "-p", "Japan", "--", "true"]) == 0
    assert seen == [SOCKET_PATH]


def test_run_numeric_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[object] = []

    def fake_run(
        policy: str | int,
        command: list[str],
        *,
        socket_path: object,
        isolation: str,
    ) -> None:
        seen.append(policy)

    monkeypatch.setattr("pyvpn.cli.run_app", fake_run)

    assert main(["run", "-p", "2", "--", "true"]) == 0
    assert seen == [2]


@pytest.mark.parametrize("policy", ["²", "٣"])
def test_run_rejects_non_ascii_numeric_policy(
    policy: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["run", "-p", f"id:{policy}", "--", "true"]) == 1
    assert "policy id must be a positive integer" in capsys.readouterr().err


def test_run_explicit_policy_name(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[object] = []

    def fake_run(
        policy: str | int,
        command: list[str],
        *,
        socket_path: object,
        isolation: str,
    ) -> None:
        seen.append(policy)

    monkeypatch.setattr("pyvpn.cli.run_app", fake_run)

    assert main(["run", "-p", "name:2", "--", "true"]) == 0
    assert seen == ["2"]


def test_rules_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "example.rules"
    path.write_text("example.com\n", encoding="utf-8")

    assert main(["rules", "check", str(path)]) == 0
    assert "domain rules" in capsys.readouterr().out


def test_rules_test_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        '{"targets":[{"name":"jp","interface":"tun0"}],'
        '"policies":[{"name":"Japan","targets":["jp"],"domains":["example.com"]}]}',
        encoding="utf-8",
    )

    assert main(["rules", "test", "example.com", "--config", str(path)]) == 0
    assert "policy 'Japan'" in capsys.readouterr().out


def test_rules_export(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        '{"targets":[{"name":"jp","interface":"tun0"}],'
        '"policies":[{"name":"Japan","targets":["jp"],"domains":["example.com"]}]}',
        encoding="utf-8",
    )

    assert main(["rules", "export", "Japan", "--config", str(path)]) == 0
    assert "example.com" in capsys.readouterr().out


def test_run_normalizes_network_namespace_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_run(*args: object, **kwargs: object) -> None:
        from pyvpn.apps.netns import NetworkNamespaceUnavailable

        raise NetworkNamespaceUnavailable("cannot create network namespace")

    monkeypatch.setattr("pyvpn.cli.run_app", fake_run)

    assert main(["run", "-p", "Japan", "--isolation", "netns", "--", "true"]) == 1
    assert "cannot create network namespace" in capsys.readouterr().err


def test_run_normalizes_missing_executable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_run(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("definitely-missing")

    monkeypatch.setattr("pyvpn.cli.run_app", fake_run)

    assert main(["run", "-p", "Japan", "--", "definitely-missing"]) == 1
    assert "definitely-missing" in capsys.readouterr().err


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


def test_enable_human_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(path, {"id": 1, "ok": True, "result": None})

    assert main(["--socket", str(path), "enable"]) == 0
    join(thread)
    assert "enable: ok" in capsys.readouterr().out


def test_enable_sends_enable_method(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    requests: list[dict[str, object]] = []

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            requests.append(json.loads(conn.makefile("rb").readline()))
            conn.sendall(b'{"id":1,"ok":true,"result":null}\n')
        server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    assert main(["--json", "--socket", str(path), "enable"]) == 0
    join(thread)
    assert requests[0]["method"] == "enable"
    assert json.loads(capsys.readouterr().out) is None


def test_enable_daemon_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "daemon.sock"
    thread = fake_daemon(
        path,
        {"id": 1, "ok": False, "error": {"code": "forbidden", "message": "root only"}},
    )

    assert main(["--socket", str(path), "enable"]) == 1
    join(thread)
    assert "root only" in capsys.readouterr().err


def test_test_lists_each_schema_problem(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        '{"version": 1, "targets": [{"name": "jp"}],'
        ' "policies": [{"name": "J", "targets": ["jp"], "on_down": "explode"}],'
        ' "bogus": 1}',
        encoding="utf-8",
    )

    assert main(["test", str(path)]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines == [
        f"{path}: error: targets.0.interface: Field required",
        f"{path}: error: policies.0.on_down: Input should be 'default' or 'block'",
        f"{path}: error: bogus: Extra inputs are not permitted",
        "errors found",
    ]


def test_test_reports_json_syntax_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"version": 1,, }', encoding="utf-8")

    assert main(["test", str(path)]) == 1
    out = capsys.readouterr().out
    assert f"error: {path}: invalid JSON at line 1, column 15" in out
    assert out.endswith("errors found\n")


def test_test_reports_unsupported_version(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"version": 99}', encoding="utf-8")

    assert main(["test", str(path)]) == 1
    assert capsys.readouterr().out == (
        f"error: {path}: unsupported configuration version 99 (supported versions: 1)\n"
        "errors found\n"
    )


def test_test_json_lists_problems(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"version": 1, "targets": [], "policies": [], "bogus": 1}', encoding="utf-8")

    assert main(["--json", "test", str(path)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["errors"] == [f"{path}: error: bogus: Extra inputs are not permitted"]
    assert result["output"].endswith("errors found\n")


def test_test_missing_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "missing.json"

    assert main(["test", str(path)]) == 1
    assert f"error: configuration file not found: {path}" in capsys.readouterr().out
