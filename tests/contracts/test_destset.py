"""DestSet drop sets (PLAN.md §3.4: ``drop:`` rules)."""

from ipaddress import IPv4Network

import pytest

from pyvpn.state import DestSet

NET = IPv4Network("192.0.2.0/24")


def test_route_sets_are_the_default() -> None:
    assert DestSet(1).drop is False


def test_drop_sets_merge_with_drop_sets_only() -> None:
    a = DestSet(1, frozenset({NET}), drop=True)
    assert (a | DestSet(1, drop=True)) == a
    with pytest.raises(ValueError, match="drop set with a route set"):
        _ = a | DestSet(1, frozenset({NET}))
