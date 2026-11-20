from __future__ import annotations

import asyncio
from ipaddress import IPv4Network

import pytest

from pyvpn.config.models import Config
from pyvpn.daemon.reconciler import Reconciler
from pyvpn.state import AppBinding, DestSet
from tests.fakes import FakeBackend, FakeDnsService
from tests.fakes.targets import down, up

NET_A = IPv4Network("10.20.0.0/16")
NET_B = IPv4Network("203.0.113.7/32")


def make(**kw: float) -> tuple[Reconciler, FakeBackend, FakeDnsService]:
    backend, dns = FakeBackend(), FakeDnsService()
    return Reconciler(backend, dns, **kw), backend, dns


async def test_applies_on_config_and_skips_unchanged(config: Config) -> None:
    r, backend, _ = make()
    await r.set_config(config)
    assert len(backend.plans) == 1
    await r.update_targets({})  # same inputs -> same plan
    await r.reconcile()
    assert len(backend.plans) == 1


async def test_flap_never_routes_block_policy_via_main(config: Config) -> None:
    r, backend, _ = make()
    await r.set_config(config)
    for statuses in (
        [up("nl", "tun0")],
        [down("nl", "tun0")],
        [],
        [up("nl", "tun1", ifindex=13)],  # VPN reconnected under a new name
        [down("nl")],
    ):
        await r.update_targets({s.name: s for s in statuses})
    torrents = [p.policies[1] for p in backend.plans]
    assert [t.route for t in torrents] == [
        "unreachable",
        "dev",
        "unreachable",
        "dev",
        "unreachable",
    ]
    assert [t.interface for t in torrents if t.route == "dev"] == ["tun0", "tun1"]
    assert all(t.route != "main" for t in torrents)


async def test_apply_failure_keeps_old_state_and_retries(config: Config) -> None:
    r, backend, _ = make(retry_initial=0.01)
    await r.set_config(config)
    backend.fail_apply = 2
    await r.update_targets({"nl": up("nl", "tun0")})
    assert r.last_error and "simulated" in r.last_error
    assert r.applied is not None and r.applied.policies[1].route == "unreachable"
    for _ in range(100):
        await asyncio.sleep(0.01)
        if r.applied.policies[1].route == "dev":
            break
    assert r.applied.policies[1].route == "dev"
    assert r.last_error is None
    await r.close()


async def test_dns_answers_take_fast_path_and_survive_reapply(config: Config) -> None:
    r, backend, dns = make()
    dns.on_answer(r.add_dests)
    await r.set_config(config)
    await dns.answer(DestSet(3, frozenset({NET_A})))
    assert backend.sets == [DestSet(3, frozenset({NET_A}))]
    assert len(backend.plans) == 1  # no full apply for a set add
    await r.reconcile()
    assert len(backend.plans) == 1  # recorded state matches installed state
    await r.update_targets({"office": up("office", "wlan1")})
    assert backend.last.policies[2].dests == DestSet(3, frozenset({NET_A}))


async def test_dns_answer_for_unfiltered_policy_is_not_pushed(config: Config) -> None:
    r, backend, _ = make()
    await r.set_config(config)
    await r.add_dests(DestSet(1, frozenset({NET_B})))
    assert backend.sets == []


async def test_set_add_failure_propagates_to_stub(config: Config) -> None:
    r, backend, _ = make()
    await r.set_config(config)
    backend.fail_add = True
    with pytest.raises(RuntimeError):
        await r.add_dests(DestSet(3, frozenset({NET_A})))


async def test_static_sets_are_merged(config: Config) -> None:
    r, backend, _ = make()
    await r.set_config(config, [DestSet(3, frozenset({NET_A})), DestSet(3, frozenset({NET_B}))])
    assert backend.last.policies[2].dests == DestSet(3, frozenset({NET_A, NET_B}))


async def test_batch_defers_apply(config: Config) -> None:
    r, backend, _ = make()
    async with r.batch():
        await r.set_config(config)
        await r.update_binding(AppBinding(1, cgroup_paths=("pyvpn.slice/p-1",)))
        assert backend.plans == []
    assert len(backend.plans) == 1
    assert backend.last.policies[0].apps.cgroup_paths == ("pyvpn.slice/p-1",)


async def test_binding_for_unknown_policy_is_ignored(config: Config) -> None:
    r, _, _ = make()
    await r.set_config(config)
    await r.update_binding(AppBinding(42))
    assert 42 not in r.bindings


async def test_dns_follows_interface_and_stops(config: Config) -> None:
    r, _, dns = make()
    await r.set_config(config)
    assert sorted(dns.running) == [1, 2]  # policy 3 has dns_via_target off
    dns.events.clear()
    await r.update_targets({"nl": up("nl", "tun0")})
    assert sorted(dns.events) == [("start", 1), ("start", 2)]
    assert dns.running[2].interface == "tun0"
    dns.events.clear()
    await r.update_targets({"nl": up("nl", "tun0")})
    assert dns.events == []
    await r.disable()
    assert dns.running == {}


async def test_disable_and_enable(config: Config) -> None:
    r, backend, _ = make()
    await r.set_config(config)
    await r.disable()
    assert backend.teardowns == 1 and r.applied is None
    await r.update_targets({"nl": up("nl", "tun0")})
    assert len(backend.plans) == 1  # nothing applied while disabled
    await r.enable()
    assert len(backend.plans) == 2 and backend.last.policies[1].route == "dev"
