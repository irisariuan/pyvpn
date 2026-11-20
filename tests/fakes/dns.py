from __future__ import annotations

from pyvpn.services import DestCallback
from pyvpn.state import DestSet, PolicyPlan


class FakeDnsService:
    def __init__(self) -> None:
        self.running: dict[int, PolicyPlan] = {}
        self.events: list[tuple[str, int]] = []
        self._cb: DestCallback | None = None

    async def start(self, plan: PolicyPlan) -> None:
        self.running[plan.policy_id] = plan
        self.events.append(("start", plan.policy_id))

    async def stop(self, policy_id: int) -> None:
        self.running.pop(policy_id, None)
        self.events.append(("stop", policy_id))

    def on_answer(self, cb: DestCallback) -> None:
        self._cb = cb

    async def answer(self, dests: DestSet) -> None:
        """Simulate a stub resolving a name: the callback runs before the reply."""
        assert self._cb is not None, "on_answer was not registered"
        await self._cb(dests)
