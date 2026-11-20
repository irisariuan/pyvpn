from __future__ import annotations

import asyncio
import inspect
from typing import Any

import pytest

from pyvpn.config.models import Config


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> bool | None:
    """Run ``async def`` tests without a pytest-asyncio dependency."""
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        args = {k: pyfuncitem.funcargs[k] for k in pyfuncitem._fixtureinfo.argnames}
        asyncio.run(asyncio.wait_for(pyfuncitem.obj(**args), timeout=10))
        return True
    return None


def make_config(**overrides: Any) -> Config:
    data: dict[str, Any] = {
        "targets": [
            {"name": "jp", "interface": "wg-jp"},
            {"name": "nl", "interface": "tun*"},
            {"name": "office", "interface": "wlan1", "gateway": "192.168.8.1"},
        ],
        "policies": [
            {
                "name": "Japan",
                "targets": ["jp", "nl"],
                "on_down": "default",
                "apps": [{"name": "firefox"}],
            },
            {
                "name": "Torrents",
                "targets": ["nl"],
                "on_down": "block",
                "apps": [{"exe": "/usr/bin/qbittorrent"}],
            },
            {
                "name": "Office",
                "targets": ["office"],
                "domains": ["corp.example"],
                "leak": {"dns_via_target": False},
            },
        ],
    }
    data.update(overrides)
    return Config.model_validate(data)


@pytest.fixture
def config() -> Config:
    return make_config()
