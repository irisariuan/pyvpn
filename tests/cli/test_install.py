from pathlib import Path

import pytest

from pyvpn.cli import main
from pyvpn.cli.install import (
    InstallError,
    InstallFile,
    desktop_file_path,
    render_desktop_file,
    render_systemd_unit,
    systemd_unit_path,
    write_install_file,
)


def test_render_systemd_unit() -> None:
    unit = render_systemd_unit("/opt/pyvpn/bin/pyvpn-daemon")
    assert "ExecStart=/opt/pyvpn/bin/pyvpn-daemon" in unit
    assert "Restart=on-failure" in unit
    assert "WantedBy=multi-user.target" in unit


def test_render_systemd_unit_rejects_multiline_executable() -> None:
    with pytest.raises(InstallError, match="control characters"):
        render_systemd_unit("/usr/bin/pyvpn\nrm")


@pytest.mark.parametrize("control", ["\x00", "\t", "\x1f", "\x7f"])
def test_render_systemd_unit_rejects_control_characters(control: str) -> None:
    with pytest.raises(InstallError, match="control characters"):
        render_systemd_unit(f"/usr/bin/pyvpn{control}")


def test_render_desktop_file() -> None:
    entry = render_desktop_file("Japan browsing")
    assert "Name=pyvpn Japan browsing" in entry
    assert 'Exec="/usr/bin/pyvpn" run -p "Japan browsing" -- %F' in entry
    assert "Terminal=true" in entry


def test_render_desktop_file_quotes_executable_with_spaces() -> None:
    entry = render_desktop_file("Japan", "/opt/My App/bin/pyvpn")
    assert 'Exec="/opt/My App/bin/pyvpn" run -p "Japan" -- %F' in entry


def test_render_desktop_file_escapes_shell_characters() -> None:
    entry = render_desktop_file("$Japan`test", "/opt/$Bin`/pyvpn")
    assert 'Exec="/opt/\\$Bin\\`/pyvpn" run -p "\\$Japan\\`test" -- %F' in entry


def test_render_desktop_file_escapes_percent_field_codes() -> None:
    entry = render_desktop_file("Japan%F", "/opt/MyApp/pyvpn%U")
    assert 'run -p "Japan%%F"' in entry
    assert 'Exec="/opt/MyApp/pyvpn%%U"' in entry


def test_render_systemd_unit_quotes_executable_with_spaces() -> None:
    unit = render_systemd_unit("/opt/My App/bin/pyvpn-daemon")
    assert 'ExecStart="/opt/My App/bin/pyvpn-daemon"' in unit


def test_render_desktop_file_rejects_empty_policy() -> None:
    with pytest.raises(InstallError, match="policy name"):
        render_desktop_file(" ")


@pytest.mark.parametrize("control", ["\x00", "\t", "\x1f", "\x7f"])
def test_render_desktop_file_rejects_control_characters(control: str) -> None:
    with pytest.raises(InstallError, match="control characters"):
        render_desktop_file(f"Japan{control}")


def test_default_install_paths() -> None:
    assert systemd_unit_path("system") == Path("/etc/systemd/system/pyvpn.service")
    assert desktop_file_path("Japan browsing", "system") == Path(
        "/usr/share/applications/pyvpn-japan-browsing.desktop"
    )


def test_write_install_file(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "pyvpn.service"
    write_install_file(InstallFile(path, "[Unit]\n"))
    assert path.read_text(encoding="utf-8") == "[Unit]\n"


def test_write_install_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "pyvpn.service"
    other = tmp_path / "other"
    other.write_text("keep", encoding="utf-8")
    target.symlink_to(other)

    with pytest.raises(InstallError, match="symlink"):
        write_install_file(InstallFile(target, "[Unit]\n"))
    assert other.read_text(encoding="utf-8") == "keep"


def test_install_dry_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["install", "--scope", "system", "--root", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "ExecStart=/usr/bin/pyvpn-daemon" in output
    assert not (tmp_path / "etc/systemd/system/pyvpn.service").exists()


def test_install_write(tmp_path: Path) -> None:
    assert (
        main(
            [
                "install",
                "--scope",
                "system",
                "--root",
                str(tmp_path),
                "--write",
            ]
        )
        == 0
    )
    path = tmp_path / "etc/systemd/system/pyvpn.service"
    assert "ExecStart=/usr/bin/pyvpn-daemon" in path.read_text(encoding="utf-8")


def test_desktop_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(
            [
                "--json",
                "desktop",
                "--policy",
                "Japan",
                "--root",
                str(tmp_path),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert '"written": false' in output
    assert "pyvpn-Japan" not in output
