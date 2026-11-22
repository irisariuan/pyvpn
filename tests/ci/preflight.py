"""Preflight for the root network-namespace job in ``ci.yml``.

Run as root before the integration suite, so a runner without cgroups v2 or
without the netlink tools fails with a clear message instead of a pile of
test errors. Exit status 0 means the suite can run.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

CGROUP_ROOT = Path("/sys/fs/cgroup")
TOOLS = ("ip", "nft", "sysctl")


def cgroup2_problem(root: Path = CGROUP_ROOT) -> str | None:
    """Why ``root`` is not a usable cgroup v2 mount, or None when it is."""
    if not (root / "cgroup.controllers").is_file():
        return f"{root} is not a cgroup v2 mount (cgroup.controllers is missing)"
    return None


def missing_tools(tools: tuple[str, ...] = TOOLS) -> list[str]:
    """The tools from ``tools`` that are not on PATH."""
    return [tool for tool in tools if shutil.which(tool) is None]


def netns_problem() -> str | None:
    """Create and delete a throwaway namespace; report why that failed."""
    name = f"pyvpn-preflight-{uuid.uuid4().hex[:8]}"
    try:
        subprocess.run(
            ["ip", "netns", "add", name],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.SubprocessError as exc:
        return f"cannot create a network namespace: {exc}"
    with contextlib.suppress(subprocess.SubprocessError):
        subprocess.run(
            ["ip", "netns", "delete", name],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    return None


def problems() -> list[str]:
    """Everything that would keep the integration suite from running."""
    found: list[str] = []
    if sys.platform != "linux":
        found.append(f"the net bed needs Linux, not {sys.platform}")
    if os.geteuid() != 0:
        found.append("the net bed needs root (run this under sudo)")
    found.extend(f"missing tool {tool!r} on PATH" for tool in missing_tools())
    for problem in (cgroup2_problem(), netns_problem()):
        if problem is not None:
            found.append(problem)
    return found


def main() -> int:
    found = problems()
    for problem in found:
        print(f"::error::{problem}", file=sys.stderr)
    if found:
        return 1
    print("netns integration preflight: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
