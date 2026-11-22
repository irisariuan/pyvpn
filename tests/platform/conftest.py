from __future__ import annotations

import asyncio
import inspect

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> bool | None:
    """Run ``async def`` tests without a pytest-asyncio dependency."""
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        args = {k: pyfuncitem.funcargs[k] for k in pyfuncitem._fixtureinfo.argnames}
        asyncio.run(asyncio.wait_for(pyfuncitem.obj(**args), timeout=10))
        return True
    return None
