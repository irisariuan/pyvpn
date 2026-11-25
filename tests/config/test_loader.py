import json
import os
from pathlib import Path

import pytest

from pyvpn.config import ConfigFileError, ConfigValidationError, load_config, load_config_text

VALID_CONFIG = """
{
  "version": 1,
  "targets": [{"name": "jp", "interface": "wg-jp"}],
  "policies": [{"name": "Japan", "targets": ["jp"], "apps": [{"name": "firefox"}]}]
}
"""


def test_load_config_text_accepts_valid_config() -> None:
    config = load_config_text(VALID_CONFIG)
    assert config.policy_id("Japan") == 1


def test_load_config_text_accepts_legacy_missing_version() -> None:
    document = json.loads(VALID_CONFIG)
    del document["version"]
    config = load_config_text(json.dumps(document))
    assert config.version == 1


def test_load_config_text_reports_json_location() -> None:
    with pytest.raises(ConfigFileError, match="invalid JSON at line 1"):
        load_config_text("{")


def test_load_config_text_reports_validation_location() -> None:
    with pytest.raises(ConfigValidationError, match="configuration validation failed") as exc:
        load_config_text(
            '{"targets":[{"name":"jp","interface":"wg-jp"}],'
            '"policies":[{"name":"bad","targets":["missing"],"apps":[{"name":"ssh"}]}]}',
            "example.json",
        )
    assert any("unknown targets" in problem for problem in exc.value.problems)


def test_load_config_reports_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigFileError, match="configuration file not found"):
        load_config(tmp_path / "missing.json")


def test_load_config_reads_json_file(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(VALID_CONFIG, encoding="utf-8")
    assert load_config(path).policy_id("Japan") == 1


_REAL_FSTAT = os.fstat


def _stat_with_uid(fd: int, uid: int) -> os.stat_result:
    real = _REAL_FSTAT(fd)
    return os.stat_result(
        (
            real.st_mode,
            real.st_ino,
            real.st_dev,
            real.st_nlink,
            uid,
            real.st_gid,
            real.st_size,
            real.st_atime,
            real.st_mtime,
            real.st_ctime,
        )
    )


@pytest.mark.parametrize("mode", [0o666, 0o664, 0o622])
def test_load_config_refuses_writable_file_when_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    path = tmp_path / "config.json"
    path.write_text(VALID_CONFIG, encoding="utf-8")
    path.chmod(mode)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(ConfigFileError, match="must not be group- or world-writable"):
        load_config(path)


def test_load_config_refuses_non_root_owned_file_when_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.json"
    path.write_text(VALID_CONFIG, encoding="utf-8")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fstat", lambda fd: _stat_with_uid(fd, 1000))
    with pytest.raises(ConfigFileError, match="must be owned by root"):
        load_config(path)


def test_load_config_accepts_root_owned_file_when_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.json"
    path.write_text(VALID_CONFIG, encoding="utf-8")
    path.chmod(0o644)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fstat", lambda fd: _stat_with_uid(fd, 0))
    assert load_config(path).policy_id("Japan") == 1


def test_load_config_ignores_mode_for_unprivileged_callers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.json"
    path.write_text(VALID_CONFIG, encoding="utf-8")
    path.chmod(0o666)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert load_config(path).policy_id("Japan") == 1


def test_load_config_rejects_unsupported_version() -> None:
    with pytest.raises(ConfigValidationError, match="unsupported configuration version 2"):
        load_config_text('{"version":2}')


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_load_config_rejects_nonfinite_json_constant(constant: str) -> None:
    with pytest.raises(ConfigFileError, match="invalid JSON constant"):
        load_config_text(f'{{"settings":{{"probe_interval":{constant}}}}}')


def test_load_config_rejects_explicit_null_version() -> None:
    with pytest.raises(ConfigValidationError, match="null is not allowed"):
        load_config_text('{"version":null,"targets":[]}')


@pytest.mark.parametrize(
    "text",
    [
        '{"version":1,"version":1,"targets":[]}',
        '{"targets":[{"name":"vpn","name":"duplicate","interface":"tun0"}]}',
    ],
)
def test_load_config_rejects_duplicate_keys(text: str) -> None:
    with pytest.raises(ConfigFileError, match="duplicate JSON key"):
        load_config_text(text)
