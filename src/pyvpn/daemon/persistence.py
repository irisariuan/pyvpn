"""Small persistent daemon state (survives restarts)."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class PersistentState:
    enabled: bool = True
    # (policy id, policy name) for every policy cgroup that may hold running
    # apps. Rules and cgroups outlive the daemon, so a restarted daemon must
    # not let a reordered config give those apps a different policy.
    policy_slots: tuple[tuple[int, str], ...] = ()


class StateError(RuntimeError):
    """The state file exists but cannot be trusted; the daemon must not start
    with defaults, which would forget reservations of live cgroups."""


def _slots(raw: object) -> tuple[tuple[int, str], ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise StateError("policy_slots is not a list")
    out: list[tuple[int, str]] = []
    for item in raw:
        if not (
            isinstance(item, list)
            and len(item) == 2
            and isinstance(item[0], int)
            and not isinstance(item[0], bool)
            and item[0] > 0
            and isinstance(item[1], str)
        ):
            raise StateError(f"bad policy slot {item!r}")
        out.append((item[0], item[1]))
    return tuple(out)


class StateStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def load(self) -> PersistentState:
        """The saved state; defaults only when no state was ever saved.

        Raises ``StateError`` for a file that exists but cannot be read or
        parsed: its cgroup reservations cannot be recovered, so starting
        with defaults could hand running apps another policy's route.
        """
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return PersistentState()
        except (OSError, ValueError) as e:
            raise StateError(f"cannot read daemon state {self.path}: {e}") from e
        if not isinstance(data, dict) or not isinstance(data.get("enabled", True), bool):
            raise StateError(f"daemon state {self.path} is malformed")
        try:
            slots = _slots(data.get("policy_slots"))
        except StateError as e:
            raise StateError(f"daemon state {self.path}: {e}") from None
        return PersistentState(enabled=data.get("enabled", True), policy_slots=slots)

    def save(self, state: PersistentState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".state-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(asdict(state), f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
