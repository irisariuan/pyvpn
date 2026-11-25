"""Real app manager implementing the daemon's Phase 0 app contract."""

from __future__ import annotations

import pwd
from collections.abc import AsyncIterator, Sequence

from pyvpn.apps.cgroups import CgroupManager
from pyvpn.apps.exclusions import expand, unsupported_exclusions
from pyvpn.config.models import AppGroup, AppSelector, Policy
from pyvpn.constants import policy_cgroup
from pyvpn.state import AppBinding


class AppManager:
    """Create policy cgroups and expose bindings to the daemon reconcile loop."""

    def __init__(self, cgroups: CgroupManager) -> None:
        self.cgroups = cgroups
        self._bindings: dict[int, AppBinding] = {}

    async def bind(self, policy_id: int, policy: Policy, groups: Sequence[AppGroup]) -> AppBinding:
        problems = unsupported_exclusions(policy, groups)
        if problems:
            # The daemon refuses such configs first; never bind one silently.
            raise ValueError(problems[0])
        if not policy.apps:
            paths: tuple[str, ...] = ()
            if policy.domains:
                self.cgroups.create(policy_id)
                paths = (policy_cgroup(policy_id),)
            binding = AppBinding(
                policy_id,
                cgroup_paths=paths,
                any_process=bool(policy.domains),
                exclude_uids=_exclude_uids(policy, groups) if policy.domains else (),
            )
        else:
            self.cgroups.create(policy_id)
            uids: set[int] = set()
            for selector in expand(policy.apps, groups):
                uid = _selector_uid(selector, policy)
                if uid is not None:
                    uids.add(uid)
            if policy.exclude_apps:
                # Keep the raw uid match for the non-excluded uids. A uid/user
                # exclusion is subtracted; a name/exe/... exclusion combined
                # with a uid selector was refused above.
                uids.difference_update(_exclude_uids(policy, groups))
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


def _selector_uid(selector: AppSelector, policy: Policy) -> int | None:
    """The uid a single app selector matches, resolving ``user``."""
    if selector.uid is not None:
        return selector.uid
    if selector.user is not None:
        try:
            return pwd.getpwnam(selector.user).pw_uid
        except KeyError:
            raise ValueError(
                f"policy {policy.name!r}: app user {selector.user!r} does not exist"
            ) from None
    return None


def _exclude_uids(policy: Policy, groups: Sequence[AppGroup]) -> tuple[int, ...]:
    """``exclude_uids`` for a policy's ``uid`` / ``user`` exclusions."""
    uids: set[int] = set()
    for selector in expand(policy.exclude_apps, groups):
        if selector.uid is not None:
            uids.add(selector.uid)
        elif selector.user is not None:
            try:
                uids.add(pwd.getpwnam(selector.user).pw_uid)
            except KeyError:
                raise ValueError(
                    f"policy {policy.name!r}: exclude_apps user {selector.user!r} does not exist"
                ) from None
    return tuple(sorted(uids))
