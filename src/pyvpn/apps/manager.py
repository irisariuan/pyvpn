"""Real app manager implementing the daemon's Phase 0 app contract."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence

from pyvpn.apps.cgroups import CgroupManager
from pyvpn.config.models import AppGroup, Policy
from pyvpn.constants import policy_cgroup
from pyvpn.state import AppBinding


class AppManager:
    """Create policy cgroups and expose bindings to the daemon reconcile loop."""

    def __init__(self, cgroups: CgroupManager) -> None:
        self.cgroups = cgroups
        self._bindings: dict[int, AppBinding] = {}

    async def bind(
        self, policy_id: int, policy: Policy, groups: Sequence[AppGroup]
    ) -> AppBinding:
        if not policy.apps:
            binding = AppBinding(policy_id, any_process=bool(policy.domains))
        else:
            self.cgroups.create(policy_id)
            group_map = {group.name: group.apps for group in groups}
            uids: set[int] = set()
            for ref in policy.apps:
                selectors = (
                    group_map.get(ref.removeprefix("group:"), ())
                    if isinstance(ref, str)
                    else (ref,)
                )
                uids.update(selector.uid for selector in selectors if selector.uid is not None)
            binding = AppBinding(
                policy_id,
                cgroup_paths=(policy_cgroup(policy_id),),
                uids=tuple(sorted(uids)),
            )
        self._bindings[policy_id] = binding
        return binding

    async def unbind(self, policy_id: int) -> None:
        self._bindings.pop(policy_id, None)
        self.cgroups.remove(policy_id)

    async def place_pid(self, pid: int, policy_id: int) -> None:
        self.cgroups.place_pid(pid, policy_id)

    def bindings(self) -> AsyncIterator[AppBinding]:
        async def generate() -> AsyncIterator[AppBinding]:
            for binding in tuple(self._bindings.values()):
                yield binding

        return generate()
