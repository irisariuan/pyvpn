"""Shared numbering conventions (Phase 0 contract, PLAN.md §3).

Policy ids are 1-based and follow the order of ``Config.policies``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

MAX_POLICIES: Final = 99

# fwmark: policy id in the low bits of a dedicated range, matched with a mask
# so marks set by other software (VPN apps, firewalld) are left alone.
FWMARK_BASE: Final = 0x5059_0000  # "PY"
FWMARK_MASK: Final = 0xFFFF_0000

TABLE_BASE: Final = 1000  # routing table = TABLE_BASE + policy id
RULE_PREF_BASE: Final = 5200  # ip rule priority = RULE_PREF_BASE + policy id
DNS_STUB_PORT_BASE: Final = 5300  # stub on 127.0.0.1:(5300 + id), i.e. "53<id>"

CGROUP_ROOT: Final = "pyvpn.slice"
NFT_TABLE: Final = "pyvpn"  # table inet pyvpn
SOCKET_PATH: Final = "/run/pyvpn/pyvpn.sock"
STATE_DIR: Final = "/var/lib/pyvpn"


def _check(policy_id: int) -> int:
    if not 1 <= policy_id <= MAX_POLICIES:
        raise ValueError(f"policy id {policy_id} out of range 1..{MAX_POLICIES}")
    return policy_id


def policy_mark(policy_id: int) -> int:
    return FWMARK_BASE | _check(policy_id)


def policy_table(policy_id: int) -> int:
    return TABLE_BASE + _check(policy_id)


def policy_rule_pref(policy_id: int) -> int:
    return RULE_PREF_BASE + _check(policy_id)


def dns_stub_port(policy_id: int) -> int:
    return DNS_STUB_PORT_BASE + _check(policy_id)


def policy_cgroup(policy_id: int) -> str:
    return f"{CGROUP_ROOT}/p-{_check(policy_id)}"


EXCLUDED_PREFIX: Final = "x-"
# "x-" + the policy-id bitmask in lowercase hex: at most 2 + 25 bytes for
# MAX_POLICIES = 99, far below NAME_MAX (255).
EXCLUDED_NAME_MAX: Final = len(EXCLUDED_PREFIX) + (MAX_POLICIES + 3) // 4


def excluded_cgroup(policy_ids: Iterable[int], app_policy_id: int | None = None) -> str:
    """Cgroup for processes the watcher moves to exempt them (PLAN.md §3.3).

    ``policy_ids`` are the destination-only policies whose ``exclude_apps``
    match the process. The leaf is ``x-<hex>``, where bit ``id - 1`` of
    ``<hex>`` (lowercase, no leading zeros) is set for each policy id: one
    cgroup per distinct set, bounded by ``EXCLUDED_NAME_MAX`` bytes and free
    of collisions, so each policy can list exactly the cgroups whose
    processes it excludes. A process that is also an app of policy
    ``app_policy_id`` stays below that policy's cgroup
    (``pyvpn.slice/p-<id>/x-<hex>``), so that policy still matches it.
    """
    ids = {_check(i) for i in policy_ids}
    if not ids:
        raise ValueError("excluded_cgroup needs at least one policy id")
    if app_policy_id is not None and app_policy_id in ids:
        raise ValueError(f"policy {app_policy_id} cannot exclude its own app")
    leaf = EXCLUDED_PREFIX + format(sum(1 << (i - 1) for i in ids), "x")
    parent = CGROUP_ROOT if app_policy_id is None else policy_cgroup(app_policy_id)
    return f"{parent}/{leaf}"


def excluded_policy_ids(path: str) -> frozenset[int] | None:
    """Policy ids encoded in an exclusion cgroup path, or None if it is not one.

    Accepts exactly what ``excluded_cgroup`` produces, so backends and the app
    manager can recognize exclusion cgroups as known (not stale) paths.
    """
    parts = path.split("/")
    if len(parts) == 2 and parts[0] == CGROUP_ROOT:
        app_policy_id = None
    elif (
        len(parts) == 3
        and parts[0] == CGROUP_ROOT
        and parts[1].startswith("p-")
        and parts[1][2:].isascii()
        and parts[1][2:].isdigit()
    ):
        app_policy_id = int(parts[1][2:])
    else:
        return None
    leaf = parts[-1]
    digits = leaf.removeprefix(EXCLUDED_PREFIX)
    if digits == leaf or not digits or any(ch not in "0123456789abcdef" for ch in digits):
        return None
    mask = int(digits, 16)
    ids = frozenset(i for i in range(1, mask.bit_length() + 1) if mask >> (i - 1) & 1)
    try:
        if excluded_cgroup(ids, app_policy_id) != path:
            return None
    except ValueError:
        return None
    return ids
