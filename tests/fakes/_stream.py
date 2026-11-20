from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Generic, TypeVar

T = TypeVar("T")
_END = object()


class Stream(Generic[T]):
    """A test-driven async stream: ``push`` items, ``end`` or ``fail`` it."""

    def __init__(self) -> None:
        self._q: asyncio.Queue[object] = asyncio.Queue()

    def push(self, item: T) -> None:
        self._q.put_nowait(item)

    def end(self) -> None:
        self._q.put_nowait(_END)

    def fail(self, exc: BaseException) -> None:
        self._q.put_nowait(exc)

    async def __aiter__(self) -> AsyncIterator[T]:
        while True:
            item = await self._q.get()
            if item is _END:
                return
            if isinstance(item, BaseException):
                raise item
            yield item  # type: ignore[misc]
