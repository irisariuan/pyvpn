"""Platform backend protocol (Phase 0 contract). Linux implementation: stream C."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol

from pyvpn.state import DestSet, RoutingPlan


@dataclass(frozen=True)
class Capabilities:
    transparent: bool = False
    user: bool = False
    proxy: bool = False
    per_app_dns: bool = False
    # ``isolation: netns`` (PLAN.md §3.6): the backend keeps a network
    # namespace for each policy plan with ``isolation="netns"`` and can start
    # commands inside it (``IsolatedLauncher``).
    netns: bool = False


class CgroupPlacer(Protocol):
    """The part of the app cgroup manager a backend needs for placement."""

    def create(self, policy_id: int) -> object: ...

    def place_pid(self, pid: int, policy_id: int, *, installed_id: int | None = None) -> object: ...


class Backend(Protocol):
    @property
    def capabilities(self) -> Capabilities: ...

    async def apply(self, plan: RoutingPlan) -> None:
        """Replace the whole installed state with ``plan``, atomically.

        Raises on failure; the previously installed state must then be intact.
        """

    async def add_to_set(self, dests: DestSet) -> None:
        """Add addresses to a policy's destination set without a full apply."""

    async def teardown(self) -> None:
        """Remove everything pyvpn installed."""

    async def spawn_isolated(
        self,
        cgroups: CgroupPlacer,
        command: IsolatedCommand,
        verify_peer: Callable[[], None],
    ) -> IsolatedProcess:
        """Start ``command`` in the policy's namespace (``isolation: netns``).

        A backend that advertises ``Capabilities.netns`` must implement this;
        the daemon refuses to start isolated policies otherwise.
        """
        ...


@dataclass(frozen=True, eq=False)
class IsolatedCommand:
    """``pyvpn run`` for an ``isolation: netns`` policy (PLAN.md §3.6).

    The unprivileged client cannot enter a namespace the daemon owns, so the
    daemon starts the command for it: inside the policy's namespace, with the
    caller's credentials, environment, working directory and standard file
    descriptors (0, 1 and 2 of ``client_pid``). ``client_pidfd`` pins the
    caller's identity so its descriptors are never taken from a reused PID.
    """

    policy_id: int
    argv: tuple[str, ...]
    env: Mapping[str, str]
    cwd: str
    umask: int
    uid: int
    gid: int
    client_pid: int
    client_pidfd: int | None = field(default=None, repr=False)


class IsolatedProcess(Protocol):
    @property
    def pid(self) -> int: ...

    async def wait(self) -> int:
        """Exit status as ``subprocess`` reports it (negative: killed by signal)."""


class IsolatedLauncher(Protocol):
    async def __call__(
        self, command: IsolatedCommand, verify_peer: Callable[[], None]
    ) -> IsolatedProcess:
        """Start ``command`` once the policy's namespace is installed.

        Raises when the namespace is not ready. ``verify_peer`` raises if the
        caller exited; it is called before the command can run.
        """
