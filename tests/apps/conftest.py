from __future__ import annotations

import asyncio
import inspect
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def daemon_socket_path() -> Iterator[Path]:
    """A daemon socket path short enough to bind everywhere.

    macOS caps AF_UNIX ``sun_path`` at 104 bytes and pytest's ``tmp_path``
    lives under ``/private/var/folders/...``, which overflows it.
    """
    with tempfile.TemporaryDirectory(prefix="pyvpn-") as tmp:
        yield Path(tmp) / "daemon.sock"


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> bool | None:
    """Run ``async def`` tests without a pytest-asyncio dependency."""
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        args = {k: pyfuncitem.funcargs[k] for k in pyfuncitem._fixtureinfo.argnames}
        asyncio.run(asyncio.wait_for(pyfuncitem.obj(**args), timeout=10))
        return True
    return None
