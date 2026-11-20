"""Process metadata extraction and configuration selector matching."""

from __future__ import annotations

import pwd
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from pyvpn.config.models import AppGroup, AppSelector, Policy


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


def read_process(pid: int, proc_root: str | Path = "/proc") -> ProcessInfo | None:
    """Read process metadata; return None when it exited or is inaccessible."""
    if pid <= 0:
        return None
    base = Path(proc_root) / str(pid)
    try:
        exe = str((base / "exe").resolve(strict=True))
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
    return ProcessInfo(pid, exe, name, uid, user, joined, flatpak, snap)


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
        value = next(iter(selector.model_dump(exclude_none=True).items()))
        field, expected = value
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
                process.flatpak is not None
                and process.flatpak.startswith(f"{expected}-")
            )
        if field == "snap":
            return process.snap == expected
        if field == "unit":
            unit = str(expected)
            return any(
                part == unit or part.endswith("/" + unit)
                for part in process.cgroup.splitlines()
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
