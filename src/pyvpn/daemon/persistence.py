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


class StateStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def load(self) -> PersistentState:
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return PersistentState()
        except (OSError, ValueError):
            # Unreadable state: start enabled; rules then fail closed per policy.
            return PersistentState()
        return PersistentState(enabled=bool(data.get("enabled", True)))

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
