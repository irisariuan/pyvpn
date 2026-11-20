"""The fakes must satisfy the contract protocols (checked by mypy)."""

from pyvpn.platform.base import Backend
from pyvpn.services import AppManager, DnsService, RuleMatcher, TargetWatcher
from tests.fakes import (
    FakeAppManager,
    FakeBackend,
    FakeDnsService,
    FakeRuleMatcher,
    FakeTargetWatcher,
)


def test_fakes_match_protocols() -> None:
    backend: Backend = FakeBackend()
    apps: AppManager = FakeAppManager()
    dns: DnsService = FakeDnsService()
    rules: RuleMatcher = FakeRuleMatcher()
    targets: TargetWatcher = FakeTargetWatcher()
    assert all((backend, apps, dns, rules, targets))
