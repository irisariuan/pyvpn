import json
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


def test_load_config_rejects_unsupported_version() -> None:
    with pytest.raises(ConfigValidationError, match="unsupported configuration version 2"):
        load_config_text('{"version":2}')


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_load_config_rejects_nonfinite_json_constant(constant: str) -> None:
    with pytest.raises(ConfigFileError, match="invalid JSON constant"):
        load_config_text(f'{{"settings":{{"probe_interval":{constant}}}}}')
