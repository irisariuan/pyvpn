from __future__ import annotations

import asyncio
import contextlib
from ipaddress import IPv4Network

import pytest

from pyvpn.config.models import Config
from pyvpn.daemon.reconciler import DnsNotGoverned, Reconciler
from pyvpn.state import AppBinding, DestSet, PolicyPlan, RoutingPlan
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
    assert sorted(dns.running) == [1, 2, 3]
    dns.events.clear()
    await r.update_targets({"nl": up("nl", "tun0")})
    # Affected stubs stop before routing changes, then restart with it.
    assert dns.events == [("stop", 1), ("stop", 2), ("start", 1), ("start", 2)]
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


class FlakyDns(FakeDnsService):
    def __init__(self) -> None:
        super().__init__()
        self.fail_start = 0

    async def start(self, plan: PolicyPlan) -> None:
        if self.fail_start:
            self.fail_start -= 1
            raise RuntimeError("bind 127.0.0.1:53xx: simulated failure")
        await super().start(plan)


async def test_dns_answer_is_refused_until_rules_are_installed(config: Config) -> None:
    r, backend, _ = make()
    with pytest.raises(DnsNotGoverned):  # nothing installed yet
        await r.add_dests(DestSet(3, frozenset({NET_A})))
    async with r.batch():
        await r.set_config(config)
        with pytest.raises(DnsNotGoverned):  # mid-batch: not installed yet
            await r.add_dests(DestSet(3, frozenset({NET_A})))
    assert backend.sets == []
    await r.add_dests(DestSet(3, frozenset({NET_A})))
    assert backend.sets == [DestSet(3, frozenset({NET_A}))]
    await r.disable()
    with pytest.raises(DnsNotGoverned):
        await r.add_dests(DestSet(3, frozenset({NET_A})))


async def test_dns_answer_pending_across_config_change_is_refused(config: Config) -> None:
    r, backend, _ = make()
    await r.set_config(config)
    async with r._lock:  # an apply is in progress; the answer waits for the lock
        pending = asyncio.ensure_future(r.add_dests(DestSet(3, frozenset({NET_A}))))
        await asyncio.sleep(0)
        r._swap_config(config, (), {})  # policy ids may now mean something else
    with pytest.raises(DnsNotGoverned):
        await pending
    assert backend.sets == []


async def test_failed_dns_start_is_retried_without_route_change(config: Config) -> None:
    backend, dns = FakeBackend(), FlakyDns()
    r = Reconciler(backend, dns, retry_initial=60)
    dns.fail_start = 1
    await r.set_config(config)
    assert 1 not in dns.running and 1 not in r.dns_applied
    assert r.last_error and "simulated" in r.last_error
    await r.reconcile()  # same routing plan, but DNS is behind
    assert len(backend.plans) == 1
    assert sorted(dns.running) == [1, 2, 3] and sorted(r.dns_applied) == [1, 2, 3]
    await r.close()


async def test_failed_dns_update_stops_stale_stub(config: Config) -> None:
    backend, dns = FakeBackend(), FlakyDns()
    r = Reconciler(backend, dns, retry_initial=60)
    await r.set_config(config)
    dns.fail_start = 1  # the update for policy 1 fails
    await r.update_targets({"jp": up("jp", "wg-jp")})
    assert 1 not in dns.running  # stopped: no stale upstream keeps answering
    await r.reconcile()
    assert dns.running[1].interface == "wg-jp"
    await r.close()


async def test_commit_config_failure_restores_previous_state(config: Config) -> None:
    r, backend, dns = make()
    await r.set_config(config)
    await r.add_dests(DestSet(3, frozenset({NET_A})))
    installed, dests = r.applied, dict(r.dynamic_dests)
    listeners = dict(dns.running)
    backend.fail_apply = 1
    other = config.model_copy(update={"policies": config.policies[:1]})
    with pytest.raises(RuntimeError):
        await r.commit_config(other, (), {1: AppBinding(1, cgroup_paths=("x",))})
    assert r.config is config and r.applied == installed and r.dynamic_dests == dests
    # Same listeners with the same DNS settings (their plans may now carry
    # the learned destinations).
    assert {k: (v.route, v.interface) for k, v in dns.running.items()} == {
        k: (v.route, v.interface) for k, v in listeners.items()
    }
    await r.add_dests(DestSet(3, frozenset({NET_B})))  # old ids still valid
    await r.close()


async def test_commit_config_keeps_old_routes_if_a_listener_cannot_stop(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, backend, dns = make()
    await r.set_config(config)
    installed, listeners = backend.installed, dict(dns.running)
    stop = dns.stop

    async def fail_second_stop(pid: int) -> None:
        await stop(pid)
        if pid == 2:
            raise RuntimeError("DNS stop failed")

    monkeypatch.setattr(dns, "stop", fail_second_stop)
    other = config.model_copy(update={"policies": config.policies[:1]})
    with pytest.raises(RuntimeError, match="DNS stop failed"):
        await r.commit_config(other, (), {})

    assert r.config is config and backend.installed is installed
    # Listener 2 reported a failed stop, so it is not restarted until a
    # stop succeeds (it might still hold its port); the others are back.
    assert dns.running == {k: v for k, v in listeners.items() if k != 2}
    assert r.last_error and "stop failed" in r.last_error
    monkeypatch.setattr(dns, "stop", stop)
    await r.reconcile()  # the pending stop now succeeds and the stub restarts
    assert sorted(dns.running) == sorted(listeners)
    await r.close()


async def test_reload_keeps_learned_dests_for_unchanged_policies(config: Config) -> None:
    r, _, _ = make()
    await r.set_config(config)
    await r.update_targets({"office": up("office", "wlan1")})
    await r.add_dests(DestSet(3, frozenset({NET_A})))

    # Same config: the learned address stays installed.
    same = config.model_copy()
    await r.commit_config(same, (), {})
    assert r.dynamic_dests == {3: DestSet(3, frozenset({NET_A}))}

    # Reordered: "Office" is now policy 1 and keeps its set under the new id.
    office, *rest = reversed(config.policies)
    reordered = config.model_copy(update={"policies": (office, *reversed(rest))})
    await r.commit_config(reordered, (), {})
    assert r.dynamic_dests == {1: DestSet(1, frozenset({NET_A}))}
    plan = r.plan()
    assert plan is not None
    office_plan = next(p for p in plan.policies if p.apps.policy_id == 1)
    assert office_plan.dests is not None and NET_A in office_plan.dests.v4

    # Changed domain rules: the learned set no longer applies.
    changed = office.model_copy(update={"domains": ("other.example",)})
    await r.commit_config(
        reordered.model_copy(update={"policies": (changed, *reordered.policies[1:])}), (), {}
    )
    assert r.dynamic_dests == {}
    await r.close()


class GatedBackend(FakeBackend):
    """``apply`` waits for ``gate`` once ``hold`` is set."""

    def __init__(self) -> None:
        super().__init__()
        self.hold = False
        self.entered = asyncio.Event()
        self.gate = asyncio.Event()

    async def apply(self, plan: RoutingPlan) -> None:
        if self.hold:
            self.entered.set()
            await self.gate.wait()
        await super().apply(plan)


async def _binding_during_commit(config: Config, *, fail: bool) -> tuple[Reconciler, AppBinding]:
    backend = GatedBackend()
    r = Reconciler(backend, FakeDnsService())
    await r.set_config(config)
    await r.update_binding(AppBinding(1, cgroup_paths=("pyvpn.slice/p-1",)))
    backend.hold, backend.fail_apply = True, int(fail)
    new = config.model_copy(update={"policies": tuple(reversed(config.policies))})
    commit = asyncio.ensure_future(r.commit_config(new, (), {}))
    await backend.entered.wait()
    # The app manager reports a binding made under the config in force now.
    late = AppBinding(1, cgroup_paths=("pyvpn.slice/p-1", "user.slice/late.scope"))
    binding = asyncio.ensure_future(r.update_binding(late))
    await asyncio.sleep(0)
    backend.gate.set()
    with contextlib.suppress(RuntimeError):
        await commit
    await binding
    return r, late


async def test_binding_sent_during_failed_commit_survives_restore(config: Config) -> None:
    r, late = await _binding_during_commit(config, fail=True)
    assert r.config is config
    assert r.bindings[1] == late  # not lost by _restore
    assert r.applied is not None and r.applied.policies[0].apps == late
    await r.close()


async def test_stale_binding_is_dropped_after_commit(config: Config) -> None:
    r, _ = await _binding_during_commit(config, fail=False)
    assert r.config is not None and r.config.policies[0].name == "Office"
    assert 1 not in r.bindings  # never attached to the policy that now has id 1
    await r.close()


async def test_additive_domain_edit_keeps_learned_dests(config: Config) -> None:
    r, _, _ = make()
    await r.set_config(config)
    await r.update_targets({"office": up("office", "wlan1")})
    await r.add_dests(DestSet(3, frozenset({NET_A})))
    office = config.policies[2]

    added = office.model_copy(update={"domains": (*office.domains, "more.example")})
    await r.commit_config(
        config.model_copy(update={"policies": (*config.policies[:2], added)}), (), {}
    )
    assert r.dynamic_dests == {3: DestSet(3, frozenset({NET_A}))}

    excluded = added.model_copy(update={"domains": (*added.domains, "!x.corp.example")})
    await r.commit_config(
        config.model_copy(update={"policies": (*config.policies[:2], excluded)}), (), {}
    )
    assert r.dynamic_dests == {}  # an exclusion may un-match learned addresses
    await r.close()


class StuckStopDns(FakeDnsService):
    def __init__(self) -> None:
        super().__init__()
        self.fail_stop = 0

    async def stop(self, policy_id: int) -> None:
        if self.fail_stop:
            self.fail_stop -= 1
            raise RuntimeError("close listener: simulated failure")
        await super().stop(policy_id)


async def test_failed_stub_stop_is_retried_until_it_succeeds(config: Config) -> None:
    backend, dns = FakeBackend(), StuckStopDns()
    r = Reconciler(backend, dns, retry_initial=60)
    await r.set_config(config)
    dns.fail_stop = 1
    await r.disable()
    assert 1 in dns.running and r.last_error and "stop failed" in r.last_error
    await r.enable()  # the pending stop is retried before the stub restarts
    assert ("stop", 1) in dns.events and sorted(dns.running) == [1, 2, 3]
    assert r.last_error is None
    await r.close()


async def test_failed_teardown_keeps_enforcing(config: Config) -> None:
    r, backend, _ = make(retry_initial=0)

    async def broken() -> None:
        raise RuntimeError("nft: teardown failed part-way")

    await r.set_config(config)
    teardown = backend.teardown
    backend.teardown = broken  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="part-way"):
        await r.disable()
    assert r.enabled and r.applied is None
    plans = len(backend.plans)
    await asyncio.sleep(0.01)  # the retry re-applies the active config
    assert len(backend.plans) == plans + 1 and r.applied is not None
    backend.teardown = teardown  # type: ignore[method-assign]
    await r.close()


async def test_close_stops_stubs_and_waits_for_a_running_retry(config: Config) -> None:
    r, backend, dns = make(retry_initial=0)
    backend.fail_apply = 1
    await r.set_config(config)  # fails, schedules a retry
    assert r._retry_task is not None
    await r.close()
    assert r._retry_task is None and dns.running == {}
    plans = len(backend.plans)
    await asyncio.sleep(0.01)
    assert len(backend.plans) == plans  # nothing applies after close


async def test_dns_only_retry_clears_its_error(config: Config) -> None:
    backend, dns = FakeBackend(), FlakyDns()
    r = Reconciler(backend, dns, retry_initial=60)
    dns.fail_start = 1
    await r.set_config(config)
    assert r.last_error
    await r.reconcile()
    assert r.last_error is None
    await r.close()
