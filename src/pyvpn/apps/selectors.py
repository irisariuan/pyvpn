"""Process metadata extraction and configuration selector matching."""

from __future__ import annotations

import os
import pwd
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from pyvpn.config.models import AppGroup, AppSelector, Policy
from pyvpn.constants import CGROUP_ROOT, excluded_cgroup, parse_excluded_cgroup, policy_cgroup


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    exe: str | None = None
    name: str | None = None
    uid: int | None = None
    user: str | None = None
    cgroup: str = ""
    flatpak: str | None = None
    snap: str | None = None
    ppid: int | None = None


def _read_exe(link: Path) -> str | None:
    """The process's executable path as the kernel reports it.

    Read with ``readlink``, not resolved: the target lives in the process's
    mount namespace (a Flatpak's ``/app/bin/...``) and may be gone after an
    upgrade (``... (deleted)``), and neither must hide the process. Raises
    ``FileNotFoundError`` for exited processes and kernel threads; returns
    None when the link is not readable (e.g. permission).
    """
    try:
        target = os.readlink(link)
    except FileNotFoundError:
        raise
    except OSError:
        return None
    return target.removesuffix(" (deleted)")


def read_process(pid: int, proc_root: str | Path = "/proc") -> ProcessInfo | None:
    """Read process metadata; return None when it exited or is inaccessible."""
    if pid <= 0:
        return None
    base = Path(proc_root) / str(pid)
    try:
        exe = _read_exe(base / "exe")
        name = (base / "comm").read_text(encoding="utf-8").strip()
        status = (base / "status").read_text(encoding="utf-8")
        cgroup = (base / "cgroup").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    uid_line = next((line for line in status.splitlines() if line.startswith("Uid:")), None)
    if uid_line is None:
        return None
    try:
        uid = int(uid_line.split()[1])
        user = pwd.getpwuid(uid).pw_name
    except (ValueError, IndexError, KeyError):
        user = None
        try:
            uid = int(uid_line.split()[1])
        except (ValueError, IndexError):
            return None
    ppid_line = next((line for line in status.splitlines() if line.startswith("PPid:")), None)
    try:
        ppid = int(ppid_line.split()[1]) if ppid_line is not None else None
    except (ValueError, IndexError):
        ppid = None
    paths = [line.split(":", 2)[-1] for line in cgroup.splitlines() if ":" in line]
    joined = "\n".join(paths)
    flatpak = None
    snap = None
    for component in joined.split("/"):
        if component.startswith("app-flatpak-"):
            flatpak = component.removeprefix("app-flatpak-").split(".scope", 1)[0]
        elif component.startswith("snap."):
            bits = component.split(".")
            if len(bits) >= 3:
                snap = bits[1]
    return ProcessInfo(pid, exe, name, uid, user, joined, flatpak, snap, ppid)


class SelectorMatcher:
    """Expand groups and match process metadata against policies."""

    def __init__(self, groups: Iterable[AppGroup] = ()) -> None:
        self.groups = {group.name: group.apps for group in groups}

    def expand(self, refs: Iterable[AppSelector | str]) -> tuple[AppSelector, ...]:
        expanded: list[AppSelector] = []
        for ref in refs:
            if isinstance(ref, AppSelector):
                expanded.append(ref)
            elif ref.startswith("group:"):
                name = ref.removeprefix("group:")
                if name not in self.groups:
                    raise ValueError(f"unknown app group {name!r}")
                expanded.extend(self.groups[name])
            else:
                raise ValueError(f"invalid app reference {ref!r}")
        return tuple(expanded)

    @staticmethod
    def matches(selector: AppSelector, process: ProcessInfo) -> bool:
        field: str
        expected: object
        field, expected = next(iter(selector.model_dump(exclude_none=True).items()))
        if field == "exe":
            return process.exe == expected
        if field == "name":
            return process.name == expected
        if field == "uid":
            return process.uid == expected
        if field == "user":
            return process.user == expected
        if field == "flatpak":
            return process.flatpak == expected or (
                process.flatpak is not None and process.flatpak.startswith(f"{expected}-")
            )
        if field == "snap":
            return process.snap == expected
        if field == "unit":
            unit = str(expected)
            return any(
                part == unit or part.endswith("/" + unit) for part in process.cgroup.splitlines()
            )
        return False

    def matches_policy(self, policy: Policy, process: ProcessInfo) -> bool:
        excluded = self.expand(policy.exclude_apps)
        if any(self.matches(selector, process) for selector in excluded):
            return False
        return any(self.matches(selector, process) for selector in self.expand(policy.apps))

    def matching_policy(self, policies: Iterable[Policy], process: ProcessInfo) -> int | None:
        for policy_id, policy in enumerate(policies, start=1):
            if self.matches_policy(policy, process):
                return policy_id
        return None

    def target(self, policies: Sequence[Policy], process: ProcessInfo, current: str) -> str | None:
        """The cgroup ``process`` belongs in, or None to leave it where it is.

        ``current`` is the pyvpn cgroup the process inherited
        (``pyvpn.slice/p-<id>`` or ``pyvpn.slice/x-<hex>``), or ``""``.
        Exclusions of policies with apps are enforced here (PLAN.md §3.3):

        1. The first policy whose ``apps`` match and whose ``exclude_apps``
           do not wins, in config order, as before.
        2. Otherwise a process that inherited ``p-<id>`` stays there unless
           that policy's ``exclude_apps`` match it.
        3. A process excluded from a policy it would otherwise join (by
           ``apps`` or by inheritance) goes to ``pyvpn.slice/x-<hex>``, the
           cgroup that names every such policy. Its descendants inherit the
           exemption from those policies only: another policy whose ``apps``
           match them still takes them, and policies that match by uid or
           destination keep governing them.
        """
        inherited_policy, inherited_excluded = self._inherited(policies, current)
        excluded = set(inherited_excluded)
        for policy_id, policy in enumerate(policies, start=1):
            if not policy.apps or policy_id in excluded:
                continue
            if not self._any(policy.apps, process):
                continue
            if self._any(policy.exclude_apps, process):
                excluded.add(policy_id)
                continue
            return policy_cgroup(policy_id)
        if inherited_policy is not None and inherited_policy not in excluded:
            if not self._any(policies[inherited_policy - 1].exclude_apps, process):
                return policy_cgroup(inherited_policy)
            excluded.add(inherited_policy)
        if excluded:
            return excluded_cgroup(excluded)
        return None

    def _any(self, refs: Iterable[AppSelector | str], process: ProcessInfo) -> bool:
        return any(self.matches(selector, process) for selector in self.expand(refs))

    @staticmethod
    def _inherited(policies: Sequence[Policy], current: str) -> tuple[int | None, frozenset[int]]:
        """The app policy and the still-valid exemptions ``current`` carries."""
        decoded = parse_excluded_cgroup(current) if current else None
        if decoded is not None and decoded.app_policy_id is None:
            # Ids are config positions; only those that still exclude apps
            # keep exempting (PLAN.md §3.3, revalidate on reload).
            valid = frozenset(
                i
                for i in decoded.policy_ids
                if i <= len(policies) and policies[i - 1].apps and policies[i - 1].exclude_apps
            )
            return None, valid
        for policy_id, policy in enumerate(policies, start=1):
            if policy.apps and current == policy_cgroup(policy_id):
                return policy_id, frozenset()
        return None, frozenset()


def pyvpn_cgroup(cgroups: str) -> str:
    """The process's pyvpn policy or exclusion cgroup, or ``""``.

    Only the exact ``pyvpn.slice/p-<id>`` and top-level ``x-<hex>`` paths
    count: those are the cgroups the watcher places processes in.
    """
    for line in cgroups.splitlines():
        path = line.strip("/")
        decoded = parse_excluded_cgroup(path)
        if decoded is not None and decoded.app_policy_id is None:
            return path
        head, _, leaf = path.partition("/")
        if head == CGROUP_ROOT and leaf.startswith("p-") and "/" not in leaf:
            return path
    return ""
