"""Autonomous system numbers -> announced prefixes. Port of snake ``internal/asn``.

Source: RIPEstat's public ``announced-prefixes`` data call
(https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes), the
prefixes RIS route collectors saw an AS originate in the last two weeks.

Prefixes are cached on disk, one JSON file per ASN (``AS<n>.json``)::

    {"version": 2, "asn": 2906, "resource": "AS2906", "source": "<url>",
     "fetched": <unix time>, "prefixes": ["198.38.0.0/19", ...]}

Version 1 files (no ``resource``) are still read, bound to the ASN in the
filename; a refresh rewrites them as version 2.

Freshness policy (PLAN.md §3.4):

- an entry younger than ``refresh_after`` (1 day) is *fresh*; ``refresh``
  skips it unless forced;
- an entry older than that is *due*: still used, ``refresh`` fetches it;
- an entry older than ``max_age`` (7 days), or one dated in the future, is
  *stale* and is never used: ``usable`` raises, so the daemon refuses to
  activate a config that needs it (fail closed) instead of routing by
  outdated prefixes.

Only ``refresh`` / ``prefixes`` touch the network. They need nothing but write
access to the cache directory, so they run unprivileged (``pyvpn asn
refresh``); the daemon itself only reads the cache. A daemon that runs as root
passes ``trusted_uids={0}``: cache files and their directory must then be
owned by root and not writable by group or others, so an unprivileged user
cannot plant prefixes that steer other users' traffic.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import stat
import tempfile
import time
import urllib.request
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import Literal

DEFAULT_URL = (
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&sourceapp=pyvpn"
)
DEFAULT_MAX_AGE = 7 * 24 * 3600.0
DEFAULT_REFRESH_AFTER = 24 * 3600.0
CACHE_VERSION = 2
MAX_PREFIXES = 250_000  # larger than any AS announces today
MIN_PREFIXLEN_V4 = 8  # nothing shorter is announced; /0 would route everything
MIN_PREFIXLEN_V6 = 16
_FUTURE_SLACK = 3600.0  # clock skew allowed on the "fetched" time
_MAX_BODY = 32 << 20

Fetcher = Callable[[str], bytes]
State = Literal["fresh", "due", "stale", "missing", "invalid"]


class AsnError(Exception):
    pass


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """treat a redirect as a failed refresh; the cache is the trusted source."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise AsnError(f"refusing redirect to {newurl}")


def _http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "pyvpn"})
    opener = urllib.request.build_opener(_RefuseRedirect())
    with opener.open(req, timeout=60) as resp:
        if resp.status != 200:
            raise AsnError(f"HTTP {resp.status}")
        body: bytes = resp.read(_MAX_BODY + 1)
    if len(body) > _MAX_BODY:
        raise AsnError("response too large")
    return body


def _default_fetch(url: str) -> bytes:
    return _http_get(url)  # looked up per call, so tests can patch it


def validate_prefixes(items: Iterable[object]) -> list[str]:
    """Normalized, de-duplicated networks; raises AsnError on anything else.

    Refuses entries that are not networks, prefixes shorter than /8 (IPv4) or
    /16 (IPv6), an empty list and implausibly long lists: a bad answer must
    never become a set that routes too much, or silently nothing.
    """
    out: dict[str, None] = {}
    for item in items:
        if not isinstance(item, str):
            raise AsnError(f"prefix {item!r} is not a string")
        try:
            net = ip_network(item.strip(), strict=False)
        except ValueError:
            raise AsnError(f"prefix {item!r} is not a network") from None
        floor = MIN_PREFIXLEN_V4 if isinstance(net, IPv4Network) else MIN_PREFIXLEN_V6
        if net.prefixlen < floor:
            raise AsnError(f"prefix {item!r} is shorter than /{floor}")
        out[str(net)] = None
        if len(out) > MAX_PREFIXES:
            raise AsnError(f"more than {MAX_PREFIXES} prefixes")
    if not out:
        raise AsnError("no prefixes announced")
    return list(out)


def parse_ripe(body: bytes, asn: int | None = None) -> list[str]:
    """Validated prefixes from a RIPEstat announced-prefixes answer.

    With ``asn``, the answer must be about that AS.
    """
    try:
        doc = json.loads(body)
        if doc.get("status", "ok") != "ok":
            raise AsnError(f"RIPEstat status {doc.get('status')!r}")
        data = doc["data"]
        if asn is not None:
            if "resource" not in data:
                raise AsnError(f"answer does not name its AS; expected AS{asn}")
            got = str(data["resource"]).upper().removeprefix("AS")
            if got != str(asn):
                raise AsnError(f"answer is for AS{got}, not AS{asn}")
        items = [p["prefix"] for p in data["prefixes"] if p.get("prefix")]
    except AsnError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise AsnError(f"bad RIPEstat answer: {e}") from None
    return validate_prefixes(items)


@dataclass(frozen=True)
class Lookup:
    prefixes: tuple[str, ...]
    error: str | None = None  # set when a refresh failed and the cache was used


@dataclass(frozen=True)
class Entry:
    """What the cache holds for one ASN (``AsnCache.entry``)."""

    asn: int
    state: State
    fetched: float | None = None
    age: float | None = None  # seconds
    prefixes: tuple[str, ...] = ()
    error: str | None = None  # why the entry is missing, invalid or stale

    @property
    def usable(self) -> bool:
        return self.state in ("fresh", "due")


@dataclass(frozen=True)
class RefreshResult:
    asn: int
    action: Literal["fetched", "skipped", "failed"]
    prefixes: int = 0
    error: str | None = None


def describe_age(seconds: float) -> str:
    if seconds < 3600:
        return f"{int(seconds // 60)} min"
    if seconds < 2 * 86400:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} days"


REFRESH_HINT = "run 'sudo pyvpn asn refresh', then 'sudo pyvpn reload'"


class AsnCache:
    def __init__(
        self,
        directory: str | os.PathLike[str],
        max_age: float = DEFAULT_MAX_AGE,
        url: str = DEFAULT_URL,
        fetch: Fetcher | None = None,
        clock: Callable[[], float] = time.time,
        refresh_after: float = DEFAULT_REFRESH_AFTER,
        trusted_uids: Collection[int] | None = None,
    ) -> None:
        self.dir = Path(directory)
        self.max_age = max_age
        self.refresh_after = min(refresh_after, max_age)
        self.url = url
        self._fetch = fetch if fetch is not None else _default_fetch
        self._clock = clock
        self.trusted_uids = frozenset(trusted_uids) if trusted_uids is not None else None

    def _path(self, n: int) -> Path:
        return self.dir / f"AS{n}.json"

    def _check_owner(self, fd: int, what: Path) -> None:
        if self.trusted_uids is None:
            return
        st = os.fstat(fd)
        if st.st_uid not in self.trusted_uids:
            raise AsnError(f"{what} is owned by uid {st.st_uid}, not by root; not trusted")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise AsnError(f"{what} is writable by group or others; not trusted")

    def _load(self, n: int) -> tuple[float, list[str]]:
        """(fetched, prefixes) from the cache file; raises FileNotFoundError
        when there is none and AsnError when it cannot be trusted or used."""
        path = self._path(n)
        try:
            if self.trusted_uids is not None:
                dfd = os.open(self.dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    self._check_owner(dfd, self.dir)
                finally:
                    os.close(dfd)
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            raise
        except OSError as e:
            raise AsnError(f"cannot read {path}: {e.strerror or e}") from None
        with os.fdopen(fd, "rb") as f:
            self._check_owner(f.fileno(), path)
            body = f.read(_MAX_BODY + 1)
        try:
            doc = json.loads(body)
            version = doc.get("version", 1)
            if version not in (1, CACHE_VERSION):
                raise AsnError(f"unknown cache version {version!r}")
            if "asn" in doc and doc["asn"] != n:
                raise AsnError(f"holds AS{doc['asn']}, not AS{n}")
            if "resource" in doc:
                got = str(doc["resource"]).upper().removeprefix("AS")
                if got != str(n):
                    raise AsnError(f"holds AS{got}, not AS{n}")
            if version == CACHE_VERSION and "asn" not in doc:
                raise AsnError(f"cache version {version} must name its ASN")
            raw = doc["fetched"]
            # NaN would compare false against every limit and never expire.
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise AsnError(f"fetched time {raw!r} is not a number")
            fetched = float(raw)
            if not math.isfinite(fetched):
                raise AsnError(f"fetched time {raw!r} is not finite")
            prefixes = validate_prefixes(doc["prefixes"])
        except AsnError as e:
            raise AsnError(f"{path}: {e}") from None
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            raise AsnError(f"{path} is not a valid cache file: {e}") from None
        return fetched, prefixes

    def entry(self, n: int) -> Entry:
        """The cache entry for ``n`` and its freshness; never fetches."""
        try:
            fetched, prefixes = self._load(n)
        except FileNotFoundError:
            return Entry(n, "missing", error=f"asn:{n} is not in the ASN cache ({self.dir})")
        except AsnError as e:
            return Entry(n, "invalid", error=f"asn:{n}: {e}")
        age = self._clock() - fetched
        if age < -_FUTURE_SLACK:
            return Entry(
                n, "stale", fetched, age, tuple(prefixes),
                f"asn:{n} cache entry is dated in the future; refusing it",
            )  # fmt: skip
        age = max(age, 0.0)
        if age >= self.max_age:
            return Entry(
                n, "stale", fetched, age, tuple(prefixes),
                f"asn:{n} cache entry is stale (fetched {describe_age(age)} ago, "
                f"limit {describe_age(self.max_age)})",
            )  # fmt: skip
        state: State = "fresh" if age < self.refresh_after else "due"
        return Entry(n, state, fetched, age, tuple(prefixes))

    def usable(self, n: int) -> list[str]:
        """Prefixes the daemon may route by: present, trusted, valid and not
        older than ``max_age``. Raises AsnError otherwise (fail closed)."""
        e = self.entry(n)
        if not e.usable:
            raise AsnError(f"{e.error}; {REFRESH_HINT}")
        return list(e.prefixes)

    def cached(self, n: int) -> list[str]:
        """Cached prefixes, fresh or stale; never fetches. Empty when there
        is no valid entry. For display only: route by ``usable``."""
        return list(self.entry(n).prefixes)

    def stale(self, n: int) -> bool:
        """True when ``refresh`` would fetch ``n`` (missing, invalid, due or stale)."""
        return self.entry(n).state != "fresh"

    def prefixes(self, n: int, force: bool = False) -> Lookup:
        """Prefixes for an ASN, fetched when the cache is not fresh (or
        ``force``). On fetch failure a usable (not stale) cache is returned
        with the error; otherwise AsnError is raised."""
        e = self.entry(n)
        if not force and e.state == "fresh":
            return Lookup(e.prefixes)
        try:
            got = parse_ripe(self._fetch(self.url.format(asn=n)), n)
        except Exception as exc:
            if e.usable:
                return Lookup(e.prefixes, f"AS{n} refresh failed, using cache: {exc}")
            raise AsnError(f"AS{n}: {exc}") from exc
        doc = {
            "version": CACHE_VERSION,
            "asn": n,
            "resource": f"AS{n}",
            "source": self.url.format(asn=n),
            "fetched": self._clock(),
            "prefixes": got,
        }
        self._write(n, json.dumps(doc, indent=0))
        return Lookup(tuple(got))

    def refresh(self, asns: Iterable[int], force: bool = False) -> list[RefreshResult]:
        """Fetch every ASN that is not fresh (all of them with ``force``).
        A failed fetch keeps the previous entry, which still expires after
        ``max_age``."""
        out = []
        for n in dict.fromkeys(asns):
            if not force and self.entry(n).state == "fresh":
                out.append(RefreshResult(n, "skipped", len(self.entry(n).prefixes)))
                continue
            try:
                got = self.prefixes(n, force=True)
            except Exception as exc:  # AsnError or a failed write
                out.append(RefreshResult(n, "failed", error=str(exc)))
                continue
            if got.error:
                out.append(RefreshResult(n, "failed", len(got.prefixes), got.error))
            else:
                out.append(RefreshResult(n, "fetched", len(got.prefixes)))
        return out

    def _write(self, n: int, text: str) -> None:
        """Replace the cache file atomically: a unique temp file in the same
        directory (concurrent refreshes do not collide), fsynced, renamed.
        Prefixes are public data: files are 0644, the directory 0755."""
        self.dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        path = self._path(n)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=path.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                os.fchmod(f.fileno(), 0o644)
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
