"""Start a command inside a policy namespace as the calling user (PLAN.md §3.6).

The daemon runs this file as root, by path and with ``python -I`` so nothing
from the caller's environment is imported: it uses the standard library
only. It reads a JSON spec from the descriptor named in ``argv[1]`` (the
daemon writes it once the process sits in the policy cgroup), then:

1. joins the network namespace, checking it is the one the daemon prepared;
2. drops to the caller's groups, gid and uid (all capabilities go with root);
3. sets the caller's umask and working directory;
4. ``exec``s the command with the caller's environment.

Standard input, output and error are already the caller's descriptors. If
the spec never arrives (the daemon gave up), nothing is executed.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import sys
from typing import Any, NoReturn

CLONE_NEWNET = 0x40000000
_SPEC_MAX = 1 << 20


def _setns(fd: int) -> None:
    native = getattr(os, "setns", None)
    if native is not None:
        native(fd, CLONE_NEWNET)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(fd, CLONE_NEWNET) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _fail(message: str, code: int = 126) -> NoReturn:
    with contextlib.suppress(OSError):
        os.write(2, f"pyvpn: {message}\n".encode(errors="replace"))
    os._exit(code)


def _read_spec(fd: int) -> dict[str, Any]:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        size += len(chunk)
        if size > _SPEC_MAX:
            _fail("launch request too large")
        chunks.append(chunk)
    os.close(fd)
    if not chunks:
        os._exit(125)  # the daemon cancelled the launch
    spec = json.loads(b"".join(chunks))
    if not isinstance(spec, dict):
        _fail("invalid launch request")
    return spec


def _capabilities_dropped() -> bool:
    try:
        with open("/proc/self/status", encoding="ascii") as status:
            for line in status:
                if line.startswith(("CapEff:", "CapPrm:")) and int(line.split()[1], 16) != 0:
                    return False
    except OSError:
        return False
    return True


def main(argv: list[str]) -> NoReturn:
    if len(argv) != 2:
        _fail("usage: nsexec <spec-fd>", 2)
    spec = _read_spec(int(argv[1]))
    try:
        netns = os.open(spec["netns"], os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        _fail(f"policy namespace is gone: {exc}")
    st = os.fstat(netns)
    if [st.st_dev, st.st_ino] != list(spec["netns_id"]):
        _fail("policy namespace was replaced; not starting the command")
    try:
        _setns(netns)
    except OSError as exc:
        _fail(f"cannot enter the policy namespace: {exc}")
    os.close(netns)

    uid, gid = int(spec["uid"]), int(spec["gid"])
    try:
        os.setgroups([int(g) for g in spec["groups"]])
        os.setresgid(gid, gid, gid)  # type: ignore[attr-defined,unused-ignore]
        os.setresuid(uid, uid, uid)  # type: ignore[attr-defined,unused-ignore]
    except OSError as exc:
        _fail(f"cannot switch to uid {uid}: {exc}")
    ids = os.getresuid()  # type: ignore[attr-defined,unused-ignore]
    if uid != 0 and (ids != (uid, uid, uid) or not _capabilities_dropped()):
        _fail("privileges were not dropped; not starting the command")

    os.umask(int(spec["umask"]) & 0o777)
    try:
        os.chdir(spec["cwd"])
    except OSError as exc:
        _fail(f"cannot enter {spec['cwd']}: {exc}")
    command = [str(a) for a in spec["argv"]]
    env = {str(k): str(v) for k, v in spec["env"].items()}
    try:
        os.execvpe(command[0], command, env)
    except OSError as exc:
        _fail(f"cannot run {command[0]}: {exc.strerror or exc}", 127)


if __name__ == "__main__":
    main(sys.argv)
