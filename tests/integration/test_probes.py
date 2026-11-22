"""Target health probes in the network test bed (PLAN.md §3.2, §8).

The probe socket is bound to one interface, so a probe can only succeed
through that interface: never through the default route. The watcher test
breaks the path behind ``vpn0`` while the link stays up (the case probes
exist for) and expects the target to go down, then come back.
"""

from __future__ import annotations

import asyncio
import select
import subprocess
import sys
import time

import pytest

from tests.integration.netbed import (
    ROOT,
    SERVICE_ADDRESS,
    TCP_PORT,
    VPN_IFACE,
    VPN_NETWORK,
    VPN_PEER,
    WAN_IFACE,
    Netbed,
)

pytestmark = pytest.mark.integration

ENDPOINT = f"{SERVICE_ADDRESS}:{TCP_PORT}"


def _connect(netbed: Netbed, interface: str) -> bool:
    result = netbed.run(
        [sys.executable, "-m", __spec__.name, "connect", interface],
        ns=netbed.host,
        cwd=ROOT,
    )
    return result.stdout.strip() == "True"


def _break_vpn_path(netbed: Netbed) -> None:
    """Drop the internet side's route back to the host over the VPN link."""
    netbed.ip("addr", "del", f"{VPN_NETWORK}.1/30", "dev", VPN_PEER, ns=netbed.internet)


def _restore_vpn_path(netbed: Netbed) -> None:
    netbed.ip("addr", "add", f"{VPN_NETWORK}.1/30", "dev", VPN_PEER, ns=netbed.internet)


def test_bound_probe_uses_only_its_interface(netbed: Netbed) -> None:
    with netbed.services() as services:
        assert _connect(netbed, VPN_IFACE)
        assert _connect(netbed, WAN_IFACE)
        assert set(services.peers("tcp")) == {f"{VPN_NETWORK}.2", "192.0.2.2"}

        _break_vpn_path(netbed)
        try:
            # The default route via the WAN still works, but the probe must
            # not fall back to it.
            assert netbed.tcp_echo() == "192.0.2.2"
            assert not _connect(netbed, VPN_IFACE)
        finally:
            _restore_vpn_path(netbed)


def _read_line(process: subprocess.Popen[str], timeout: float) -> str:
    assert process.stdout is not None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([process.stdout], [], [], 0.1)
        if ready:
            line = process.stdout.readline()
            if not line:
                break
            return line.strip()
    raise AssertionError(f"no status line within {timeout}s")


def test_watcher_drops_a_dead_tunnel_and_brings_it_back(netbed: Netbed) -> None:
    with netbed.services():
        process = subprocess.Popen(
            [*netbed._enter(netbed.host), sys.executable, "-m", __spec__.name, "watch"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert _read_line(process, 10) == "down"  # fail closed before the first probe
            assert _read_line(process, 10) == "up"
            _break_vpn_path(netbed)
            try:
                assert _read_line(process, 10) == "down"
            finally:
                _restore_vpn_path(netbed)
            assert _read_line(process, 10) == "up"
        finally:
            process.kill()
            process.wait(timeout=5)


async def _watch() -> None:
    from pyvpn.config.models import Settings, Target
    from pyvpn.platform.linux.netlink import NetlinkTargetWatcher

    target = Target(name="vpn", interface=VPN_IFACE, probe=True)
    settings = Settings(probe_targets=(ENDPOINT,), probe_interval=0.2)
    async for statuses in NetlinkTargetWatcher((target,), settings=settings).statuses():
        print("up" if statuses["vpn"].usable else "down", flush=True)


def main(argv: list[str]) -> None:
    from pyvpn.platform.linux.netlink import tcp_connect_bound

    if argv[:1] == ["connect"]:
        print(tcp_connect_bound(argv[1], SERVICE_ADDRESS, TCP_PORT, 2.0))
    elif argv == ["watch"]:
        asyncio.run(_watch())
    else:
        raise SystemExit("usage: test_probes connect IFACE | watch")


if __name__ == "__main__":
    main(sys.argv[1:])
