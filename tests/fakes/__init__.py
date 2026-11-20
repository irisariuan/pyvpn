"""Fakes of every cross-stream interface (Phase 0 contract)."""

from tests.fakes.apps import FakeAppManager
from tests.fakes.backend import FakeBackend
from tests.fakes.dns import FakeDnsService
from tests.fakes.rules import FakeRuleMatcher
from tests.fakes.targets import FakeTargetWatcher

__all__ = [
    "FakeAppManager",
    "FakeBackend",
    "FakeDnsService",
    "FakeRuleMatcher",
    "FakeTargetWatcher",
]
