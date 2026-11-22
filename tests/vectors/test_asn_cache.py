"""The on-disk ASN prefix cache: freshness, validation, trust and refresh.

Uses the fixture cache in ``data/asn`` and the RIPEstat answer in
``data/ripe``; nothing here touches the network.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from ipaddress import ip_network
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pyvpn.cli import main
from pyvpn.config.models import Config
from pyvpn.daemon.main import asn_cache_problem
from pyvpn.match import RuleConfigError, build_matcher
from pyvpn.match.asn import AsnCache, AsnError, parse_ripe, validate_prefixes
from pyvpn.rulefile import commands

DATA = Path(__file__).parent / "data"
FETCHED = 1790000000.0  # "fetched" in data/asn/AS2906.json
HOUR = 3600.0
DAY = 24 * HOUR
FIXTURE_PREFIXES = ["198.45.48.0/24", "2a00:86c0:2014::/48", "23.246.0.0/18"]
RIPE = (DATA / "ripe" / "AS2906.json").read_bytes()


def _config(*domains: str) -> Config:
    return Config.model_validate(
        {
            "targets": [{"name": "jp", "interface": "wg-jp"}],
            "policies": [{"name": "stream", "targets": ["jp"], "domains": list(domains)}],
        }
    )


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    d = tmp_path / "asn"
    shutil.copytree(DATA / "asn", d)
    return d


def _cache(directory: Path, now: float, **kw: Any) -> AsnCache:
    def offline(url: str) -> bytes:
        raise AssertionError(f"unexpected fetch {url}")

    kw.setdefault("fetch", offline)
    return AsnCache(directory, clock=lambda: now, **kw)


def _write(directory: Path, n: int, doc: object) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"AS{n}.json").write_text(json.dumps(doc))


# --- freshness -------------------------------------------------------------


def test_fixture_entry_is_fresh_then_due_then_stale(cache_dir: Path) -> None:
    fresh = _cache(cache_dir, FETCHED + HOUR).entry(2906)
    assert fresh.state == "fresh" and fresh.usable and list(fresh.prefixes) == FIXTURE_PREFIXES
    assert fresh.age == HOUR

    due = _cache(cache_dir, FETCHED + 2 * DAY)
    assert due.entry(2906).state == "due" and due.usable(2906) == FIXTURE_PREFIXES

    stale = _cache(cache_dir, FETCHED + 8 * DAY)
    e = stale.entry(2906)
    assert e.state == "stale" and not e.usable
    assert "stale (fetched 8.0 days ago, limit 7.0 days)" in (e.error or "")
    with pytest.raises(AsnError, match=r"stale .*pyvpn asn refresh"):
        stale.usable(2906)
    assert stale.cached(2906) == FIXTURE_PREFIXES  # display only


def test_future_dated_entry_is_refused(cache_dir: Path) -> None:
    c = _cache(cache_dir, FETCHED - 2 * HOUR)
    assert c.entry(2906).state == "stale"
    with pytest.raises(AsnError, match="future"):
        c.usable(2906)
    assert _cache(cache_dir, FETCHED - 60).entry(2906).state == "fresh"  # small skew is fine


def test_missing_entry(tmp_path: Path) -> None:
    e = _cache(tmp_path / "nothing", FETCHED).entry(13335)
    assert e.state == "missing" and "asn:13335 is not in the ASN cache" in (e.error or "")


# --- validation ------------------------------------------------------------


@pytest.mark.parametrize(
    ("doc", "reason"),
    [
        ({"version": 1, "asn": 2906, "fetched": FETCHED, "prefixes": ["nope"]}, "not a network"),
        ({"version": 1, "asn": 2906, "fetched": FETCHED, "prefixes": ["0.0.0.0/0"]}, "/8"),
        ({"version": 1, "asn": 2906, "fetched": FETCHED, "prefixes": ["::/8"]}, "/16"),
        ({"version": 1, "asn": 2906, "fetched": FETCHED, "prefixes": []}, "no prefixes"),
        ({"version": 1, "asn": 2906, "fetched": FETCHED, "prefixes": [1]}, "not a string"),
        ({"version": 1, "asn": 1, "fetched": FETCHED, "prefixes": ["1.0.0.0/24"]}, "not AS2906"),
        ({"version": 9, "fetched": FETCHED, "prefixes": ["1.0.0.0/24"]}, "version"),
        ({"version": 1, "prefixes": ["1.0.0.0/24"]}, "not a valid cache file"),
        (["1.0.0.0/24"], "not a valid cache file"),
        ({"version": 1, "fetched": float("nan"), "prefixes": ["1.0.0.0/24"]}, "not finite"),
        ({"version": 1, "fetched": float("inf"), "prefixes": ["1.0.0.0/24"]}, "not finite"),
        ({"version": 1, "fetched": float("-inf"), "prefixes": ["1.0.0.0/24"]}, "not finite"),
        ({"version": 1, "fetched": "nan", "prefixes": ["1.0.0.0/24"]}, "not a number"),
        ({"version": 1, "fetched": True, "prefixes": ["1.0.0.0/24"]}, "not a number"),
    ],
)
def test_invalid_entries_are_refused(tmp_path: Path, doc: object, reason: str) -> None:
    _write(tmp_path, 2906, doc)
    e = _cache(tmp_path, FETCHED).entry(2906)
    assert e.state == "invalid" and reason in (e.error or "")
    with pytest.raises(RuleConfigError, match="asn:2906"):
        build_matcher(_config("asn:2906"), _cache(tmp_path, FETCHED))


def test_prefixes_are_normalized_and_deduplicated() -> None:
    assert validate_prefixes(["10.1.2.3/8", "10.0.0.0/8", " 2001:db8::1/32"]) == [
        "10.0.0.0/8",
        "2001:db8::/32",
    ]


def test_parse_ripe_fixture() -> None:
    assert parse_ripe(RIPE, 2906) == FIXTURE_PREFIXES  # duplicates removed
    with pytest.raises(AsnError, match="not AS13335"):
        parse_ripe(RIPE, 13335)
    with pytest.raises(AsnError, match="status"):
        parse_ripe(json.dumps({"status": "error", "data": {}}).encode())
    with pytest.raises(AsnError, match="/8"):
        parse_ripe(json.dumps({"data": {"prefixes": [{"prefix": "0.0.0.0/1"}]}}).encode())


# --- trust -----------------------------------------------------------------


def test_untrusted_owner_is_refused(cache_dir: Path) -> None:
    me = os.geteuid()
    assert _cache(cache_dir, FETCHED, trusted_uids={me}).entry(2906).usable
    e = _cache(cache_dir, FETCHED, trusted_uids={me + 1}).entry(2906)
    assert e.state == "invalid" and "not by root" in (e.error or "")


def test_group_writable_file_or_directory_is_refused(cache_dir: Path) -> None:
    me = {os.geteuid()}
    path = cache_dir / "AS2906.json"
    path.chmod(0o664)
    assert "writable by group" in (
        _cache(cache_dir, FETCHED, trusted_uids=me).entry(2906).error or ""
    )
    path.chmod(0o644)
    cache_dir.chmod(0o777)
    try:
        e = _cache(cache_dir, FETCHED, trusted_uids=me).entry(2906)
        assert e.state == "invalid" and str(cache_dir) in (e.error or "")
    finally:
        cache_dir.chmod(0o755)


def test_symlinked_entry_is_refused(cache_dir: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    shutil.move(cache_dir / "AS2906.json", target)
    (cache_dir / "AS2906.json").symlink_to(target)
    assert _cache(cache_dir, FETCHED).entry(2906).state == "invalid"


# --- refresh ---------------------------------------------------------------


def test_refresh_fetches_due_entries_and_skips_fresh_ones(tmp_path: Path) -> None:
    d = tmp_path / "asn"
    calls: list[str] = []

    def fetch(url: str) -> bytes:
        calls.append(url)
        return RIPE

    now = [FETCHED]
    c = AsnCache(d, fetch=fetch, clock=lambda: now[0])
    [r] = c.refresh([2906, 2906])
    assert (r.action, r.prefixes) == ("fetched", 3) and len(calls) == 1
    doc = json.loads((d / "AS2906.json").read_text())
    assert doc["version"] == 1 and doc["asn"] == 2906 and doc["fetched"] == FETCHED
    assert doc["prefixes"] == FIXTURE_PREFIXES and "stat.ripe.net" in doc["source"]
    assert stat.S_IMODE((d / "AS2906.json").stat().st_mode) == 0o644

    assert c.refresh([2906])[0].action == "skipped" and len(calls) == 1
    assert c.refresh([2906], force=True)[0].action == "fetched" and len(calls) == 2
    now[0] += 2 * DAY
    assert c.refresh([2906])[0].action == "fetched" and len(calls) == 3


def test_failed_refresh_keeps_the_old_entry_until_it_expires(cache_dir: Path) -> None:
    def broken(url: str) -> bytes:
        raise OSError("network unreachable")

    due = AsnCache(cache_dir, fetch=broken, clock=lambda: FETCHED + 2 * DAY)
    [r] = due.refresh([2906])
    assert r.action == "failed" and "network unreachable" in (r.error or "")
    assert due.usable(2906) == FIXTURE_PREFIXES

    expired = AsnCache(cache_dir, fetch=broken, clock=lambda: FETCHED + 8 * DAY)
    assert expired.refresh([2906])[0].action == "failed"
    with pytest.raises(AsnError, match="stale"):
        expired.usable(2906)


def test_bad_answer_never_replaces_the_cache(cache_dir: Path) -> None:
    before = (cache_dir / "AS2906.json").read_bytes()
    empty = json.dumps({"status": "ok", "data": {"resource": "2906", "prefixes": []}}).encode()
    c = AsnCache(cache_dir, fetch=lambda url: empty, clock=lambda: FETCHED + 2 * DAY)
    assert c.refresh([2906])[0].action == "failed"
    assert (cache_dir / "AS2906.json").read_bytes() == before


# --- matcher, checks and status -------------------------------------------


def test_matcher_expands_asn_from_the_fixture_cache(cache_dir: Path) -> None:
    c = _cache(cache_dir, FETCHED + HOUR)
    m = build_matcher(_config("asn:AS2906", "cidr:192.0.2.0/24"), c)
    (cache_dir / "AS2906.json").unlink()  # the matcher read the cache once
    [ds] = m.static_sets()
    assert ds.v4 == {
        ip_network("198.45.48.0/24"),
        ip_network("23.246.0.0/18"),
        ip_network("192.0.2.0/24"),
    }
    assert ds.v6 == {ip_network("2a00:86c0:2014::/48")}


def test_stale_cache_refuses_activation(cache_dir: Path) -> None:
    with pytest.raises(RuleConfigError, match=r"policy 'stream': asn:2906 cache entry is stale"):
        build_matcher(_config("asn:2906"), _cache(cache_dir, FETCHED + 8 * DAY))


def test_config_check_reports_cache_state(cache_dir: Path) -> None:
    cfg = _config("asn:2906")
    ok = commands.check_config(cfg, _cache(cache_dir, FETCHED).usable)
    assert ok.code == 0
    bad = commands.check_config(cfg, _cache(cache_dir, FETCHED + 8 * DAY).usable)
    assert bad.code == 1 and "policy 'stream': error: asn:2906 cache entry is stale" in bad.output


def test_rule_file_check_warns_about_cache(cache_dir: Path) -> None:
    res = commands.check(
        "netflix.com\nasn:2906\nasn:13335\n",
        "x.rules",
        asn_prefixes=_cache(cache_dir, FETCHED).usable,
    )
    assert res.code == 0  # the file is fine; the cache is a warning
    assert "x.rules: warning: asn:13335 is not in the ASN cache" in res.output
    assert "asn:2906" not in res.output.replace("2 ASNs", "")


def test_asn_status_and_refresh_commands(cache_dir: Path) -> None:
    out = commands.asn_status(_cache(cache_dir, FETCHED + 2 * DAY), [2906])
    assert (
        out.code == 0 and "asn:2906: 3 prefixes, fetched 2.0 days ago (refresh due)" in out.output
    )
    out = commands.asn_status(_cache(cache_dir, FETCHED + 8 * DAY), [2906, 13335])
    assert out.code == 1
    assert "asn:2906: error: stale:" in out.output and "asn:13335: error: missing:" in out.output

    c = AsnCache(cache_dir, fetch=lambda url: RIPE, clock=lambda: FETCHED + 8 * DAY)
    out = commands.asn_refresh(c, [2906])
    assert out.code == 0 and "asn:2906: fetched 3 prefixes" in out.output
    assert "sudo pyvpn reload" in out.output


def test_daemon_reports_entries_that_go_stale(cache_dir: Path) -> None:
    daemon: Any = SimpleNamespace(reconciler=SimpleNamespace(config=_config("asn:2906")))
    assert asn_cache_problem(daemon, _cache(cache_dir, FETCHED + HOUR)) == ""
    problem = asn_cache_problem(daemon, _cache(cache_dir, FETCHED + 8 * DAY))
    assert problem.startswith("ASN cache: asn:2906 cache entry is stale")
    assert "installed prefixes stay in force" in problem
    daemon.reconciler.config = None
    assert asn_cache_problem(daemon, _cache(cache_dir, FETCHED + 8 * DAY)) == ""


# --- CLI -------------------------------------------------------------------


def _config_file(tmp_path: Path, *domains: str) -> Path:
    path = tmp_path / "config.json"
    path.write_text(_config(*domains).model_dump_json())
    return path


def test_cli_asn_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _config_file(tmp_path, "asn:2906")
    d = tmp_path / "cache"
    monkeypatch.setattr("pyvpn.match.asn._http_get", lambda url: RIPE)
    assert main(["asn", "status", "--config", str(cfg), "--asn-cache", str(d)]) == 1
    assert "asn:2906: error: missing" in capsys.readouterr().out
    assert main(["test", str(cfg), "--asn-cache", str(d)]) == 1
    assert "asn:2906 is not in the ASN cache" in capsys.readouterr().out

    assert main(["asn", "refresh", "--config", str(cfg), "--asn-cache", str(d)]) == 0
    assert "asn:2906: fetched 3 prefixes" in capsys.readouterr().out
    assert main(["--json", "asn", "status", "AS2906", "--asn-cache", str(d)]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] and doc["entries"][0]["state"] == "fresh"
    assert main(["test", str(cfg), "--asn-cache", str(d)]) == 0
    assert main(["asn", "status", "nope", "--asn-cache", str(d)]) == 1
    assert "invalid ASN" in capsys.readouterr().err
