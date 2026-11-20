"""Autonomous system numbers -> announced prefixes. Port of snake ``internal/asn``.

Prefixes are cached per ASN on disk. ``cached`` never touches the network, so
it is safe on the reconcile path; ``prefixes`` refreshes stale entries and is
meant to run off the event loop (e.g. ``asyncio.to_thread``).
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

DEFAULT_URL = (
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&sourceapp=pyvpn"
)
DEFAULT_MAX_AGE = 7 * 24 * 3600.0
_MAX_BODY = 32 << 20

Fetcher = Callable[[str], bytes]


class AsnError(Exception):
    pass


def _http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "pyvpn"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        if resp.status != 200:
            raise AsnError(f"HTTP {resp.status}")
        body: bytes = resp.read(_MAX_BODY + 1)
    if len(body) > _MAX_BODY:
        raise AsnError("response too large")
    return body


def parse_ripe(body: bytes) -> list[str]:
    """Prefixes from a RIPEstat announced-prefixes answer."""
    try:
        doc = json.loads(body)
        items = doc["data"]["prefixes"]
        out = [str(p["prefix"]) for p in items if p.get("prefix")]
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise AsnError(f"bad RIPEstat answer: {e}") from None
    if not out:
        raise AsnError("no prefixes announced")
    return out


@dataclass(frozen=True)
class Lookup:
    prefixes: tuple[str, ...]
    error: str | None = None  # set when a refresh failed and the cache was used


class AsnCache:
    def __init__(
        self,
        directory: str | os.PathLike[str],
        max_age: float = DEFAULT_MAX_AGE,
        url: str = DEFAULT_URL,
        fetch: Fetcher = _http_get,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.dir = Path(directory)
        self.max_age = max_age
        self.url = url
        self._fetch = fetch
        self._clock = clock

    def _path(self, n: int) -> Path:
        return self.dir / f"AS{n}.json"

    def _read(self, n: int) -> tuple[float, list[str]]:
        try:
            doc = json.loads(self._path(n).read_text())
            return float(doc["fetched"]), [str(p) for p in doc["prefixes"]]
        except (OSError, ValueError, KeyError, TypeError):
            return 0.0, []

    def cached(self, n: int) -> list[str]:
        """Cached prefixes, fresh or stale; never fetches."""
        return self._read(n)[1]

    def stale(self, n: int) -> bool:
        fetched, prefixes = self._read(n)
        return not prefixes or self._clock() - fetched >= self.max_age

    def prefixes(self, n: int, force: bool = False) -> Lookup:
        """Prefixes for an ASN, fetched when the cache is stale (or ``force``).
        On fetch failure a stale cache is returned with the error; with no
        cache, AsnError is raised."""
        fetched, cached = self._read(n)
        if not force and cached and self._clock() - fetched < self.max_age:
            return Lookup(tuple(cached))
        try:
            got = parse_ripe(self._fetch(self.url.format(asn=n)))
        except Exception as e:
            if cached:
                return Lookup(tuple(cached), f"AS{n} refresh failed, using cache: {e}")
            raise AsnError(f"AS{n}: {e}") from e
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self._path(n).with_suffix(".tmp")
        tmp.write_text(json.dumps({"fetched": self._clock(), "prefixes": got}))
        tmp.replace(self._path(n))
        return Lookup(tuple(got))
