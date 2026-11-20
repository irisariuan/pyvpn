import json

import pytest
from pydantic import ValidationError

from pyvpn.config.models import AppSelector, Config

PLAN_EXAMPLE = """
{
  "version": 1,
  "targets": [
    {"name": "jp",     "interface": "wg-jp"},
    {"name": "nl",     "interface": "tun*", "probe": true},
    {"name": "office", "interface": "wlan1", "gateway": "auto"}
  ],
  "app_groups": [{"name": "browsers", "apps": [{"exe": "/usr/bin/firefox"},
                                               {"flatpak": "com.google.Chrome"}]}],
  "policies": [
    {"name": "Japan browsing", "targets": ["jp", "nl"], "on_down": "default",
     "apps": ["group:browsers", {"name": "steam"}],
     "leak": {"dns_via_target": true, "dns_server": "9.9.9.9", "dns_protocol": "dot",
              "block_doh": true, "block_dot": true, "ipv6": "route"}},
    {"name": "Torrents", "targets": ["nl"], "on_down": "block", "isolation": "netns",
     "apps": [{"exe": "/usr/bin/qbittorrent"}], "leak": {"ipv6": "block"}},
    {"name": "Office", "targets": ["office"],
     "apps": [{"name": "ssh"}, {"name": "remmina"}],
     "domains": ["corp.example", "cidr:10.20.0.0/16"]}
  ],
  "settings": {"probe_targets": ["1.1.1.1:443"], "probe_interval": 15}
}
"""


def test_plan_example_parses() -> None:
    cfg = Config.model_validate_json(PLAN_EXAMPLE)
    assert [p.name for p in cfg.policies] == ["Japan browsing", "Torrents", "Office"]
    assert cfg.policy_id("Torrents") == 2
    assert cfg.policies[0].apps[0] == "group:browsers"
    assert cfg.policies[1].on_down == "block"


def test_unknown_target_rejected() -> None:
    data = json.loads(PLAN_EXAMPLE)
    data["policies"][0]["targets"] = ["mars"]
    with pytest.raises(ValidationError, match="unknown targets"):
        Config.model_validate(data)


def test_unknown_field_rejected() -> None:
    with pytest.raises(ValidationError):
        Config.model_validate({"targetz": []})


def test_selector_needs_exactly_one_field() -> None:
    with pytest.raises(ValidationError):
        AppSelector(exe="/bin/a", name="a")
    with pytest.raises(ValidationError):
        AppSelector()


def test_policy_needs_scope() -> None:
    with pytest.raises(ValidationError, match="needs apps"):
        Config.model_validate(
            {
                "targets": [{"name": "a", "interface": "x"}],
                "policies": [{"name": "p", "targets": ["a"]}],
            }
        )
