"""Shared numbering conventions (Phase 0 contract, PLAN.md §3).

Policy ids are 1-based and follow the order of ``Config.policies``.
"""

from __future__ import annotations

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
