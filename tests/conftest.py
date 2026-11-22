"""Fixtures shared by the whole test tree (stream I).

The test bed is the only thing here. Unit tests never touch it: its fixture
skips unless the process is root on Linux, and the integration marker keeps it
out of the default run (see ``[tool.pytest.ini_options]``).
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests.integration.netbed import Netbed


@pytest.fixture
def netbed() -> Iterator[Netbed]:
    """A throwaway two-namespace network bed (PLAN.md §8)."""
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.skip("the network test bed needs root on Linux (PLAN.md §8)")
    from tests.integration.netbed import Netbed

    bed = Netbed.build()
    try:
        yield bed
    finally:
        bed.destroy()
