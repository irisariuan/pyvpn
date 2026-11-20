from __future__ import annotations

import os

import pytest

from pyvpn.apps.netns import NetworkNamespaceUnavailable, enter_network_namespace


def test_netns_helper_reports_missing_unshare(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "unshare", raising=False)
    with pytest.raises(NetworkNamespaceUnavailable, match="unavailable"):
        enter_network_namespace()
