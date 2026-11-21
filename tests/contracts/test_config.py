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


def test_duplicate_target_names_rejected() -> None:
    with pytest.raises(ValidationError, match="target names must be unique"):
        Config.model_validate(
            {
                "targets": [
                    {"name": "vpn", "interface": "tun0"},
                    {"name": "vpn", "interface": "tun1"},
                ],
                "policies": [{"name": "p", "targets": ["vpn"], "apps": [{"name": "ssh"}]}],
            }
        )


def test_duplicate_policy_names_rejected() -> None:
    with pytest.raises(ValidationError, match="policy names must be unique"):
        Config.model_validate(
            {
                "targets": [{"name": "vpn", "interface": "tun0"}],
                "policies": [
                    {"name": "p", "targets": ["vpn"], "apps": [{"name": "ssh"}]},
                    {"name": "p", "targets": ["vpn"], "apps": [{"name": "git"}]},
                ],
            }
        )


def test_unknown_app_group_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown app group"):
        Config.model_validate(
            {
                "targets": [{"name": "vpn", "interface": "tun0"}],
                "policies": [{"name": "p", "targets": ["vpn"], "apps": ["group:missing"]}],
            }
        )


def test_policy_needs_target() -> None:
    with pytest.raises(ValidationError, match="needs at least one target"):
        Config.model_validate(
            {
                "targets": [{"name": "vpn", "interface": "tun0"}],
                "policies": [{"name": "p", "targets": [], "apps": [{"name": "ssh"}]}],
            }
        )


def test_probe_interval_must_be_positive() -> None:
    with pytest.raises(ValidationError, match="greater than zero"):
        Config.model_validate(
            {
                "targets": [{"name": "vpn", "interface": "tun0"}],
                "policies": [{"name": "p", "targets": ["vpn"], "apps": [{"name": "ssh"}]}],
                "settings": {"probe_interval": 0},
            }
        )


def test_probe_interval_must_be_finite() -> None:
    with pytest.raises(ValidationError, match="finite"):
        Config.model_validate(
            {
                "targets": [{"name": "vpn", "interface": "tun0"}],
                "policies": [{"name": "p", "targets": ["vpn"], "apps": [{"name": "ssh"}]}],
                "settings": {"probe_interval": "Infinity"},
            }
        )


@pytest.mark.parametrize(
    "target",
    [
        "example.com:443",
        "1.1.1.1",
        "1.1.1.1:0",
        "1.1.1.1:65536",
        "[2001:db8::1",
    ],
)
def test_probe_targets_must_use_ip_and_port(target: str) -> None:
    with pytest.raises(ValidationError):
        Config.model_validate(
            {
                "targets": [{"name": "vpn", "interface": "tun0"}],
                "policies": [{"name": "p", "targets": ["vpn"], "apps": [{"name": "ssh"}]}],
                "settings": {"probe_targets": [target]},
            }
        )


@pytest.mark.parametrize("target", ["1.1.1.1:443", "[2001:db8::1]:443"])
def test_probe_targets_accept_ips(target: str) -> None:
    config = Config.model_validate(
        {
            "targets": [{"name": "vpn", "interface": "tun0"}],
            "policies": [{"name": "p", "targets": ["vpn"], "apps": [{"name": "ssh"}]}],
            "settings": {"probe_targets": [target]},
        }
    )
    assert target in config.settings.probe_targets


@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_app_string_selectors_must_not_be_empty(value: str) -> None:
    with pytest.raises(ValidationError, match="must not be empty"):
        AppSelector(name=value)


@pytest.mark.parametrize("uid", [-1, 4294967295])
def test_uid_must_be_in_range(uid: int) -> None:
    with pytest.raises(ValidationError, match="uid must be between"):
        AppSelector(uid=uid)


@pytest.mark.parametrize(
    "dns_server",
    [
        "",
        " ",
        "example.com",
        "dns.example@",
        "@192.0.2.53",
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "fe80::1%eth0",
    ],
)
def test_dns_server_must_be_remote_unicast_or_tls_address(dns_server: str) -> None:
    with pytest.raises(ValidationError):
        Config.model_validate(
            {
                "targets": [{"name": "vpn", "interface": "tun0"}],
                "policies": [
                    {
                        "name": "p",
                        "targets": ["vpn"],
                        "apps": [{"name": "ssh"}],
                        "leak": {"dns_server": dns_server},
                    }
                ],
                "settings": {"probe_interval": 15},
            }
        )


@pytest.mark.parametrize(
    "dns_server",
    ["9.9.9.9", "2001:4860:4860::8888", "dns.quad9.net@9.9.9.9"],
)
def test_dns_server_accepts_remote_unicast_or_tls_address(dns_server: str) -> None:
    config = Config.model_validate(
        {
            "targets": [{"name": "vpn", "interface": "tun0"}],
            "policies": [
                {
                    "name": "p",
                    "targets": ["vpn"],
                    "apps": [{"name": "ssh"}],
                    "leak": {
                        "dns_server": dns_server,
                        "dns_protocol": "dot" if "@" in dns_server else "plain",
                    },
                }
            ],
        }
    )
    assert config.policies[0].leak.dns_server == dns_server


@pytest.mark.parametrize("uid", [True, False])
def test_uid_rejects_boolean(uid: bool) -> None:
    with pytest.raises(ValidationError):
        AppSelector(uid=uid)


@pytest.mark.parametrize("interval", [True, False])
def test_probe_interval_rejects_boolean(interval: bool) -> None:
    with pytest.raises(ValidationError):
        Config.model_validate(
            {
                "targets": [{"name": "vpn", "interface": "tun0"}],
                "policies": [{"name": "p", "targets": ["vpn"], "apps": [{"name": "ssh"}]}],
                "settings": {"probe_interval": interval},
            }
        )


@pytest.mark.parametrize(
    "field",
    ["probe", "dns_via_target", "block_doh", "block_dot", "block_quic"],
)
def test_boolean_fields_reject_strings(field: str) -> None:
    with pytest.raises(ValidationError):
        if field == "probe":
            Config.model_validate(
                {
                    "targets": [{"name": "vpn", "interface": "tun0", "probe": "true"}],
                    "policies": [{"name": "p", "targets": ["vpn"], "apps": [{"name": "ssh"}]}],
                }
            )
        else:
            Config.model_validate(
                {
                    "targets": [{"name": "vpn", "interface": "tun0"}],
                    "policies": [
                        {
                            "name": "p",
                            "targets": ["vpn"],
                            "apps": [{"name": "ssh"}],
                            "leak": {field: "true"},
                        }
                    ],
                }
            )
