"""Pure builders for pyvpn systemd and desktop installation files."""

from __future__ import annotations

import os
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


class InstallError(RuntimeError):
    """an installation file could not be validated or written."""


InstallScope = Literal["system", "user"]


@dataclass(frozen=True)
class InstallFile:
    """one installable file and its destination."""

    path: Path
    content: str


def render_systemd_unit(exec_start: str = "/usr/bin/pyvpn-daemon") -> str:
    """render the root systemd unit."""
    if not exec_start.strip():
        raise InstallError("daemon executable must not be empty")
    if any(ord(character) < 32 or ord(character) == 127 for character in exec_start):
        raise InstallError("daemon executable must not contain control characters")
    escaped = exec_start.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("$", "$$").replace("%", "%%")
    needs_quotes = any(
        character.isspace() or character in '"\\$%;&|<>*?[](){}' for character in exec_start
    )
    rendered_exec = f'"{escaped}"' if needs_quotes else escaped

    return (
        "[Unit]\n"
        "Description=pyvpn policy routing daemon\n"
        "After=network-pre.target\n"
        "Before=shutdown.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={rendered_exec}\n"
        "Restart=on-failure\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def _desktop_escape(value: str) -> str:
    """escape a value for a Desktop Entry Exec field."""
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InstallError("desktop entry values must not contain control characters")
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("`", "\\`")
        .replace("%", "%%")
    )


def render_desktop_file(
    policy: str,
    executable: str = "/usr/bin/pyvpn",
) -> str:
    """render a desktop launcher for one policy."""
    if not policy.strip():
        raise InstallError("policy name must not be empty")
    if not executable.strip():
        raise InstallError("launcher executable must not be empty")
    policy_argument = f"name:{policy}"

    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name=pyvpn {policy}\n"
        f'Exec="{_desktop_escape(executable)}" run -p "{_desktop_escape(policy_argument)}" -- %F\n'
        "Terminal=true\n"
        "Categories=Network;\n"
    )


def systemd_unit_path(scope: InstallScope = "system") -> Path:
    """return the default unit destination for one install scope."""
    if scope == "user":
        config_home = os.environ.get("XDG_CONFIG_HOME")
        base = Path(config_home) if config_home else Path.home() / ".config"
        return base / "systemd" / "user" / "pyvpn.service"
    return Path("/etc/systemd/system/pyvpn.service")


def desktop_file_path(policy: str, scope: InstallScope = "system") -> Path:
    """return the default desktop launcher destination."""
    if not policy.strip():
        raise InstallError("policy name must not be empty")
    safe_name = "".join(character.lower() if character.isalnum() else "-" for character in policy)
    safe_name = "-".join(filter(None, safe_name.split("-")))
    if not safe_name:
        raise InstallError("policy name has no usable desktop-file name")

    if scope == "user":
        base = (
            Path(os.environ["XDG_DATA_HOME"])
            if os.environ.get("XDG_DATA_HOME")
            else Path.home() / ".local" / "share"
        )
        return base / "applications" / f"pyvpn-{safe_name}.desktop"
    return Path("/usr/share/applications") / f"pyvpn-{safe_name}.desktop"


def write_install_file(file: InstallFile) -> None:
    """create a parent directory and write one install file."""
    try:
        file.path.parent.mkdir(parents=True, exist_ok=True)
        if file.path.is_symlink():
            raise InstallError(f"install destination is a symlink: {file.path}")
        try:
            mode = file.path.stat(follow_symlinks=False).st_mode
        except FileNotFoundError:
            mode = None
        if mode is not None and not stat.S_ISREG(mode):
            raise InstallError(f"install destination is not a regular file: {file.path}")

        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{file.path.name}.",
            dir=file.path.parent,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(file.content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o644)
            os.replace(temporary, file.path)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(temporary)
            raise
    except OSError as exc:
        raise InstallError(f"cannot write install file {file.path}: {exc}") from exc
