"""Run every vector with both regex engines.

CI installs ``google-re2`` (the ``dev`` extra), so without this the default
installation's Python ``re`` path would hardly be tested. Rules are compiled
when parsed, so patching ``pattern._re2`` before a test makes it use ``re``.
"""

from __future__ import annotations

import pytest

from pyvpn.match import pattern


@pytest.fixture(autouse=True, params=["re2", "re"])
def regex_engine(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    engine = str(request.param)
    if engine == "re":
        monkeypatch.setattr(pattern, "_re2", None)
    elif pattern.regex_engine() != "re2":
        pytest.skip("google-re2 is not installed")
    return engine
