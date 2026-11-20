from __future__ import annotations

from collections.abc import AsyncIterator

from pyvpn.state import TargetStatus
from tests.fakes._stream import Stream


def up(name: str, interface: str, ifindex: int = 10, **kw: object) -> TargetStatus:
    return TargetStatus(name, interface, ifindex, True, **kw)  # type: ignore[arg-type]


def down(name: str, interface: str | None = None) -> TargetStatus:
    return TargetStatus(name, interface, None, False)


class FakeTargetWatcher:
    def __init__(self) -> None:
        self.stream: Stream[dict[str, TargetStatus]] = Stream()

    def push(self, *statuses: TargetStatus) -> None:
        self.stream.push({s.name: s for s in statuses})

    def statuses(self) -> AsyncIterator[dict[str, TargetStatus]]:
        return self.stream.__aiter__()
