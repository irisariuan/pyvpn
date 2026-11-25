from __future__ import annotations

from collections.abc import Callable

from pyvpn.platform.base import (
    Capabilities,
    CgroupPlacer,
    IsolatedCommand,
    IsolatedProcess,
)
from pyvpn.state import DestSet, RoutingPlan


class FakeBackend:
    """Records every call. Set ``fail_apply`` to make the next applies raise.

    ``netns=True`` reports the ``netns`` capability (``isolation: netns``).
    """

    def __init__(self, *, netns: bool = False) -> None:
        self.netns = netns
        self.plans: list[RoutingPlan] = []
        self.sets: list[DestSet] = []
        self.teardowns = 0
        self.fail_apply = 0
        self.fail_add = False
        self.installed: RoutingPlan | None = None

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(transparent=True, user=True, per_app_dns=True, netns=self.netns)

    async def apply(self, plan: RoutingPlan) -> None:
        if self.fail_apply:
            self.fail_apply -= 1
            raise RuntimeError("nft: simulated failure")
        self.plans.append(plan)
        self.installed = plan

    async def add_to_set(self, dests: DestSet) -> None:
        if self.fail_add:
            raise RuntimeError("nft: set add failed")
        self.sets.append(dests)

    async def teardown(self) -> None:
        self.teardowns += 1
        self.installed = None

    async def spawn_isolated(
        self,
        cgroups: CgroupPlacer,
        command: IsolatedCommand,
        verify_peer: Callable[[], None],
    ) -> IsolatedProcess:
        raise NotImplementedError("FakeBackend does not start isolated commands")

    @property
    def last(self) -> RoutingPlan:
        return self.plans[-1]
