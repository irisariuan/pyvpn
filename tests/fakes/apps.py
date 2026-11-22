from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence

from pyvpn.config.models import AppGroup, AppSelector, Policy
from pyvpn.constants import policy_cgroup
from pyvpn.state import AppBinding
from tests.fakes._stream import Stream


class FakeAppManager:
    """Binds each policy with apps to its ``pyvpn.slice/p-<id>`` cgroup.

    A destination-only policy binds ``any_process``. Its ``exclude_apps``
    map to binding fields (PLAN.md §3.3):

    - ``unit`` / ``flatpak`` / ``snap``: the app's existing cgroup, looked up
      in ``cgroups`` by ``(field, value)``; nothing is moved.
    - ``uid``: ``exclude_uids``; ``user``: looked up in ``users``.
    - ``exe`` / ``name``: deferred. A cgroup set by an executable match
      outlives an ``exec``, so it cannot be revoked before the new program
      opens a socket; these selectors are reported unresolved and exempt
      nothing.

    A selector the fake cannot resolve gives no exemption (fail closed) and
    is recorded in ``unresolved``.

    The real app manager supports only ``uid`` / ``user`` here for now, and
    the daemon refuses the other kinds (``apps.exclusions``). The fake keeps
    mapping ``unit`` / ``flatpak`` / ``snap`` so the backend's handling of
    ``exclude_cgroup_paths`` stays covered.
    """

    def __init__(
        self,
        *,
        cgroups: Mapping[tuple[str, str], str] | None = None,
        users: Mapping[str, int] | None = None,
    ) -> None:
        self.stream: Stream[AppBinding] = Stream()
        self.bound: dict[int, Policy] = {}
        self.placed: list[tuple[int, int]] = []
        self.unbound: list[int] = []
        self.cgroups: Mapping[tuple[str, str], str] = cgroups or {}
        self.users: Mapping[str, int] = users or {}
        self.unresolved: list[tuple[int, AppSelector]] = []

    async def bind(self, policy_id: int, policy: Policy, groups: Sequence[AppGroup]) -> AppBinding:
        self.bound[policy_id] = policy
        if not policy.apps:
            return self._exclusions(policy_id, policy, groups)
        return AppBinding(policy_id, cgroup_paths=(policy_cgroup(policy_id),))

    def _exclusions(self, policy_id: int, policy: Policy, groups: Sequence[AppGroup]) -> AppBinding:
        group_map = {group.name: group.apps for group in groups}
        selectors = [
            selector
            for ref in policy.exclude_apps
            for selector in (
                group_map.get(ref.removeprefix("group:"), ()) if isinstance(ref, str) else (ref,)
            )
        ]
        paths: list[str] = []
        uids: set[int] = set()
        for sel in selectors:
            path: str | None = None
            if sel.uid is not None:
                uids.add(sel.uid)
                continue
            if sel.user is not None:
                if sel.user in self.users:
                    uids.add(self.users[sel.user])
                else:
                    self.unresolved.append((policy_id, sel))
                continue
            if sel.exe is not None or sel.name is not None:
                # Deferred: the exemption cannot be revoked before a new
                # executable opens a socket (PLAN.md §3.3).
                self.unresolved.append((policy_id, sel))
                continue
            if sel.unit is not None or sel.flatpak is not None or sel.snap is not None:
                key = next(
                    (f, v)
                    for f in ("unit", "flatpak", "snap")
                    if (v := getattr(sel, f)) is not None
                )
                path = self.cgroups.get(key)
                if path is None:
                    self.unresolved.append((policy_id, sel))
                    continue
            if path is None:  # pragma: no cover - AppSelector sets one field
                self.unresolved.append((policy_id, sel))
                continue
            if path not in paths:
                paths.append(path)
        return AppBinding(
            policy_id,
            any_process=True,
            exclude_cgroup_paths=tuple(paths),
            exclude_uids=tuple(sorted(uids)),
        )

    async def unbind(self, policy_id: int) -> None:
        self.unbound.append(policy_id)
        self.bound.pop(policy_id, None)

    async def place_pid(self, pid: int, policy_id: int) -> None:
        self.placed.append((pid, policy_id))

    def bindings(self) -> AsyncIterator[AppBinding]:
        return self.stream.__aiter__()
