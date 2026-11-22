"""nft script rendering refuses anything it cannot quote safely."""

from __future__ import annotations

from dataclasses import replace

import pytest

from pyvpn.netfilter import build_ruleset
from pyvpn.netfilter.render import render
from pyvpn.state import AppBinding, RoutingPlan
from tests.netfilter.test_ruleset import policy


@pytest.mark.parametrize("name", ['wg"; flush ruleset', "wg\njp", "a\\b", "wg;x"])
def test_unsafe_interface_names_are_refused(name: str) -> None:
    with pytest.raises(ValueError, match="unsafe"):
        render(build_ruleset(RoutingPlan((policy(interface=name),))))


def test_unsafe_cgroup_paths_are_refused() -> None:
    apps = AppBinding(1, cgroup_paths=('x" accept; #',))
    with pytest.raises(ValueError, match="unsafe"):
        render(build_ruleset(RoutingPlan((replace(policy(), apps=apps),))))


def test_unknown_commands_are_refused() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        render({"nftables": [{"flush": {"ruleset": None}}]})
    with pytest.raises(ValueError, match="unsupported"):
        render(
            {
                "nftables": [
                    {
                        "add": {
                            "rule": {
                                "family": "inet",
                                "table": "t",
                                "chain": "c",
                                "expr": [{"counter": None}],
                            }
                        }
                    }
                ]
            }
        )
