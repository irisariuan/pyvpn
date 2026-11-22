"""Safe cgroup v2 operations for pyvpn policy processes."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterable
from pathlib import Path

from pyvpn.constants import (
    CGROUP_ROOT,
    EXCLUDED_PREFIX,
    MAX_POLICIES,
    excluded_cgroup,
    parse_excluded_cgroup,
    policy_cgroup,
)


class CgroupError(RuntimeError):
    """A cgroup operation could not be completed."""


class CgroupManager:
    """Manage ``pyvpn.slice/p-<id>`` beneath a cgroup v2 mount.

    ``root`` is the cgroup2 mount (or a temporary directory in tests). The
    manager never mounts or changes the host's cgroup hierarchy itself.
    """

    def __init__(self, root: str | Path = "/sys/fs/cgroup") -> None:
        self.root = Path(root)
        self.slice = self.root / CGROUP_ROOT

    @staticmethod
    def _validate(policy_id: int) -> None:
        if not 1 <= policy_id <= MAX_POLICIES:
            raise ValueError(f"policy id must be in 1..{MAX_POLICIES}")

    def create(self, policy_id: int) -> Path:
        self._validate(policy_id)
        if not (self.root / "cgroup.controllers").exists() and self.root == Path("/sys/fs/cgroup"):
            raise CgroupError("cgroup v2 is not mounted at /sys/fs/cgroup")
        self.slice.mkdir(parents=True, exist_ok=True)
        path = self.root / policy_cgroup(policy_id)
        path.mkdir(exist_ok=True)
        return path

    def create_excluded(self, policy_ids: Iterable[int]) -> Path:
        """Create ``pyvpn.slice/x-<hex>`` for processes exempt from ``policy_ids``.

        The backend treats an existing top-level ``x-<hex>`` cgroup as a known
        child of ``pyvpn.slice`` (PLAN.md §3.3). Until a ruleset that knows it
        is installed, its sockets are rejected, never routed around a policy.
        """
        if not (self.root / "cgroup.controllers").exists() and self.root == Path("/sys/fs/cgroup"):
            raise CgroupError("cgroup v2 is not mounted at /sys/fs/cgroup")
        path = self.root / excluded_cgroup(policy_ids)
        self.slice.mkdir(parents=True, exist_ok=True)
        path.mkdir(exist_ok=True)
        return path

    def place_excluded(self, pid: int, policy_ids: Iterable[int]) -> Path:
        """Move ``pid`` out of its policy cgroup into ``x-<hex>``."""
        if pid <= 0:
            raise ValueError("pid must be positive")
        path = self.create_excluded(policy_ids)
        try:
            (path / "cgroup.procs").write_text(f"{pid}\n", encoding="ascii")
        except OSError as exc:
            raise CgroupError(f"cannot place pid {pid} in {path}: {exc}") from exc
        return path

    def remove_excluded(self, policy_id: int) -> None:
        """Remove empty ``x-<hex>`` cgroups that name ``policy_id``."""
        self._validate(policy_id)
        for child in self._excluded_children():
            decoded = parse_excluded_cgroup(f"{CGROUP_ROOT}/{child.name}")
            if decoded is not None and policy_id in decoded.policy_ids:
                # Still has members: they stay governed by other policies.
                with contextlib.suppress(OSError):
                    child.rmdir()

    def _excluded_children(self) -> list[Path]:
        if not self.slice.is_dir():
            return []
        return sorted(
            child
            for child in self.slice.glob(f"{EXCLUDED_PREFIX}*")
            if parse_excluded_cgroup(f"{CGROUP_ROOT}/{child.name}") is not None
        )

    def place_pid(self, pid: int, policy_id: int, *, installed_id: int | None = None) -> Path:
        """Place a PID, optionally requiring the exact cgroup installed by nft."""
        if pid <= 0:
            raise ValueError("pid must be positive")
        path = self.create(policy_id) if installed_id is None else self.path_for(policy_id)
        try:
            if installed_id is None:
                (path / "cgroup.procs").write_text(f"{pid}\n", encoding="ascii")
            else:
                directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    if os.fstat(directory).st_ino != installed_id:
                        raise CgroupError(f"routing rules for {path} are stale")
                    # Open relative to the checked directory. If it was
                    # removed, this cannot open a replacement's cgroup.procs.
                    procs = os.open("cgroup.procs", os.O_WRONLY | os.O_TRUNC, dir_fd=directory)
                    with os.fdopen(procs, "w", encoding="ascii") as stream:
                        stream.write(f"{pid}\n")
                finally:
                    os.close(directory)
        except OSError as exc:
            raise CgroupError(f"cannot place pid {pid} in {path}: {exc}") from exc
        return path

    def path_for(self, policy_id: int) -> Path:
        self._validate(policy_id)
        return self.root / policy_cgroup(policy_id)

    def remove(self, policy_id: int) -> None:
        path = self.path_for(policy_id)
        try:
            path.rmdir()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise CgroupError(f"cannot remove non-empty cgroup {path}: {exc}") from exc

    def remove_all(self) -> None:
        if not self.slice.exists():
            return
        for child in [*sorted(self.slice.glob("p-*")), *self._excluded_children()]:
            try:
                child.rmdir()
            except OSError as exc:
                raise CgroupError(f"cannot remove cgroup {child}: {exc}") from exc
        try:
            self.slice.rmdir()
        except OSError as exc:
            raise CgroupError(f"cannot remove cgroup slice {self.slice}: {exc}") from exc

    def cgroup_path(self, policy_id: int) -> str:
        return policy_cgroup(policy_id)
