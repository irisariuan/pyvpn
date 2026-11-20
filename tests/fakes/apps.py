from __future__ import annotations

from collections.abc import AsyncIterator, Sequence

from pyvpn.config.models import AppGroup, Policy
from pyvpn.constants import policy_cgroup
from pyvpn.state import AppBinding
from tests.fakes._stream import Stream


class FakeAppManager:
    """Binds each policy with apps to its ``pyvpn.slice/p-<id>`` cgroup."""

    def __init__(self) -> None:
        self.stream: Stream[AppBinding] = Stream()
        self.bound: dict[int, Policy] = {}
        self.placed: list[tuple[int, int]] = []
        self.unbound: list[int] = []

    async def bind(self, policy_id: int, policy: Policy, groups: Sequence[AppGroup]) -> AppBinding:
        self.bound[policy_id] = policy
        if not policy.apps:
            return AppBinding(policy_id, any_process=True)
        return AppBinding(policy_id, cgroup_paths=(policy_cgroup(policy_id),))

    async def unbind(self, policy_id: int) -> None:
        self.unbound.append(policy_id)
        self.bound.pop(policy_id, None)

    async def place_pid(self, pid: int, policy_id: int) -> None:
        self.placed.append((pid, policy_id))

    def bindings(self) -> AsyncIterator[AppBinding]:
        return self.stream.__aiter__()
