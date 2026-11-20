"""Safe cgroup v2 operations for pyvpn policy processes."""

from __future__ import annotations

from pathlib import Path

from pyvpn.constants import CGROUP_ROOT, MAX_POLICIES, policy_cgroup


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

    def place_pid(self, pid: int, policy_id: int) -> Path:
        if pid <= 0:
            raise ValueError("pid must be positive")
        path = self.create(policy_id)
        procs = path / "cgroup.procs"
        try:
            procs.write_text(f"{pid}\n", encoding="ascii")
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
        for child in sorted(self.slice.glob("p-*")):
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
