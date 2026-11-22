"""The RuleMatcher built from a config, the ASN cache and the rules commands."""

from __future__ import annotations

import json
from ipaddress import ip_network
from pathlib import Path

import pytest

from pyvpn.config.models import Config
from pyvpn.match import PolicyMatcher, RuleConfigError, build_matcher, matcher_factory
from pyvpn.match.asn import AsnCache, AsnError, parse_ripe
from pyvpn.rulefile import commands
from pyvpn.services import RuleMatcher, RuleMatcherFactory


def _config(*policies: dict[str, object]) -> Config:
    return Config.model_validate(
        {"targets": [{"name": "jp", "interface": "wg-jp"}], "policies": list(policies)}
    )


CFG = _config(
    {"name": "apps-only", "targets": ["jp"], "apps": [{"name": "steam"}]},
    {
        "name": "stream",
        "targets": ["jp"],
        "domains": ["netflix.com", "**.nflxvideo.net", "!=ads.netflix.com", "drop:ads.tv",
                    "cidr:23.246.0.0/18", "ip:2001:db8::1", "asn:AS2906"],
    },
    {"name": "office", "targets": ["jp"], "domains": ["ads.netflix.com", "corp.example",
                                                      "session:s.example"]},
)  # fmt: skip


ACTIVE = _config(
    {"name": "stream", "targets": ["jp"], "domains": ["netflix.com", "cidr:23.246.0.0/18"]},
)


def test_is_a_rule_matcher() -> None:
    factory: RuleMatcherFactory = build_matcher
    m: RuleMatcher = factory(ACTIVE)
    assert m.match("www.netflix.com") == 1


def test_runtime_rejects_unparsable_rules() -> None:
    cfg = _config({"name": "p", "targets": ["jp"], "domains": ["ok.example", "bad domain"]})
    with pytest.raises(RuleConfigError, match=r"policy 'p' rule 2: .*bad domain"):
        build_matcher(cfg)


def test_runtime_activates_drop_rules() -> None:
    cfg = _config(
        {
            "name": "a",
            "targets": ["jp"],
            "domains": ["drop:ads.tv", "drop:cidr:203.0.113.0/24", "drop:ip:2001:db8::7",
                        "drop:asn:64500", "cidr:198.51.100.0/24"],
        },
        {"name": "b", "targets": ["jp"], "domains": ["ads.tv", "ok.example"]},
    )  # fmt: skip
    m = build_matcher(cfg, _FakeAsnCache({64500: ["192.0.2.0/24"]}))  # type: ignore[arg-type]
    assert m.problems() == []
    # The drop claims the name: policy "b" never routes it, and the stub puts
    # its addresses into policy "a"'s drop set.
    assert m.match("x.ads.tv") is None
    assert m.decide_chain("x.ads.tv") == (1, True)
    assert m.decide_chain("cdn.example", "x.ads.tv") == (1, True)
    assert m.decide_chain("ok.example") == (2, False)
    assert m.decide_chain("nothing.example") is None
    route, drop = m.static_sets()
    assert not route.drop and route.v4 == {ip_network("198.51.100.0/24")}
    assert drop.drop and drop.policy_id == 1
    assert drop.v4 == {ip_network("203.0.113.0/24"), ip_network("192.0.2.0/24")}
    assert drop.v6 == {ip_network("2001:db8::7/128")}
    assert m.asns() == [64500]
    assert m.policies[0].has_drops and not m.policies[1].has_drops
    assert commands.check_config(cfg, lambda n: ["192.0.2.0/24"]).code == 0
    out = commands.explain_config(cfg, ["x.ads.tv"])
    assert out.code == 1 and "blocked by policy 'a'" in out.output


class _FakeAsnCache:
    def __init__(self, prefixes: dict[int, list[str]]) -> None:
        self._prefixes = prefixes

    def cached(self, asn: int) -> list[str]:
        return self._prefixes.get(asn, [])

    def usable(self, asn: int) -> list[str]:
        if asn not in self._prefixes:
            raise AsnError(f"asn:{asn} is not in the ASN cache")
        return self._prefixes[asn]


def test_drop_asn_without_prefixes_is_refused() -> None:
    cfg = _config({"name": "a", "targets": ["jp"], "domains": ["drop:asn:64500"]})
    with pytest.raises(RuleConfigError, match="asn:64500 needs the ASN cache"):
        build_matcher(cfg)
    with pytest.raises(RuleConfigError, match="asn:64500 is not in the ASN cache"):
        build_matcher(cfg, _FakeAsnCache({}))  # type: ignore[arg-type]


def test_drop_sessions_stay_refused() -> None:
    cfg = _config({"name": "a", "targets": ["jp"], "domains": ["drop[ttl=5m]:ads.tv"]})
    m = PolicyMatcher.from_config(cfg)
    assert m.policies[0].unsupported() == ["drop[ttl=5m]:ads.tv"]
    with pytest.raises(RuleConfigError, match="per-device rules are not supported yet"):
        build_matcher(cfg)


@pytest.mark.parametrize(
    "rule",
    [
        "session:**.example.com",
        "route:example.com",
        "if:example.com;then:drop:ads.example",
        "if:a.example;then:drop:example.com",
        "if:a.example;then:route:b.example;else:drop:example.com",
    ],
)
def test_runtime_rejects_per_device_rules(rule: str) -> None:
    cfg = _config({"name": "p", "targets": ["jp"], "domains": [rule, "example.com"]})
    lenient = PolicyMatcher.from_config(cfg)
    hidden = lenient.match("www.example.com") is None
    if not rule.startswith("if:example.com"):
        # Leniently built, the per-device rule hides the plain rule...
        assert hidden
    # ...so activation fails and problems() says why,
    [problem] = lenient.problems()
    assert problem == f"policy 'p': per-device rules are not supported yet: {rule}"
    with pytest.raises(RuleConfigError, match="per-device rules are not supported yet"):
        build_matcher(cfg)
    # rules check fails, and rules test does not just say "no policy".
    res = commands.check_config(cfg)
    assert res.code == 1 and "error: not supported by pyvpn yet, the daemon refuses" in res.output
    if hidden:
        out = commands.explain_config(cfg, ["www.example.com"]).output
        assert "skipped policy 'p': per-device rule" in out


REGEX_CFG = _config(
    {"name": "safe", "targets": ["jp"], "domains": ["*.a.example", "**.cdn-*.b.example"]},
    {"name": "re", "targets": ["jp"],
     "domains": ["c.example", r"/^ipv4-c\d+\.x\.net$/", "**.d.**.example", r"!/^ads\./"]},
)  # fmt: skip


def test_runtime_requires_re2_for_regex_rules(regex_engine: str) -> None:
    if regex_engine == "re2":
        m = build_matcher(REGEX_CFG)
        assert m.match("ipv4-c1.x.net") == 2 and m.match("ads.c.example") is None
        assert "re2" not in commands.check_config(REGEX_CFG).output
        return
    # Python's re backtracks: refuse rules that could stall the DNS path.
    with pytest.raises(RuleConfigError) as e:
        build_matcher(REGEX_CFG)
    msg = str(e.value)
    assert "policy 'safe'" not in msg  # bounded wildcards are fine with re
    for pos in (2, 3, 4):
        assert f"policy 're' rule {pos}: " in msg
    assert "snakevpn[re2]" in msg
    # rules check still parses them and warns.
    res = commands.check_config(REGEX_CFG)
    assert res.code == 0 and "policy 're' rule 2: warning:" in res.output
    assert "snakevpn[re2]" in res.output
    assert "warning:" in commands.check(r"/^a+$/" + "\n").output
    # The lenient matcher still matches (rules test, rules check).
    assert PolicyMatcher.from_config(REGEX_CFG).match("ipv4-c1.x.net") == 2


def test_redos_rule_is_refused_without_re2(monkeypatch: pytest.MonkeyPatch) -> None:
    from pyvpn.match import pattern

    monkeypatch.setattr(pattern, "_re2", None)
    cfg = _config({"name": "p", "targets": ["jp"], "domains": [r"/^(a+)+$/"]})
    with pytest.raises(RuleConfigError, match=r"policy 'p' rule 1: .*google-re2"):
        build_matcher(cfg)


def test_runtime_asn_rules_use_the_cache(tmp_path: Path) -> None:
    cfg = _config({"name": "asn-only", "targets": ["jp"], "domains": ["asn:AS2906"]})
    with pytest.raises(RuleConfigError, match="asn:2906 needs the ASN cache"):
        build_matcher(cfg)
    cache = AsnCache(tmp_path, fetch=lambda url: _ripe("198.38.96.0/19"))
    factory = matcher_factory(cache)
    with pytest.raises(RuleConfigError, match="asn:2906 is not in the ASN cache"):
        factory(cfg)
    cache.prefixes(2906)
    [ds] = factory(cfg).static_sets()
    assert ds.policy_id == 1 and ds.v4 == {ip_network("198.38.96.0/19")}


def test_first_policy_wins_and_exclusions_fall_through() -> None:
    m = PolicyMatcher.from_config(CFG)
    assert m.match("NetFlix.com.") == 2
    assert m.match("ads.netflix.com") == 3  # excluded from "stream", routed by "office"
    assert m.match("x.corp.example") == 3
    assert m.match("unrelated.test") is None
    assert m.match("") is None
    # CNAME chain
    assert m.match_chain("movies.partner.tv", "abc.nflxvideo.net") == 2
    d = m.explain("ads.netflix.com")
    assert d.excluded_by == (("stream", "!=ads.netflix.com"),) and d.policy == "office"


def test_drop_and_sessions_route_nothing() -> None:
    m = PolicyMatcher.from_config(CFG)
    d = m.explain("x.ads.tv")
    assert d.action == "drop" and d.policy_id == 2 and m.match("x.ads.tv") is None
    assert m.match("s.example") is None
    assert m.policies[1].unsupported() == ["session:s.example"]
    assert m.policies[0].unsupported() == []


def test_static_sets() -> None:
    m = PolicyMatcher.from_config(CFG)
    [ds] = m.static_sets()
    assert ds.policy_id == 2
    assert ds.v4 == {ip_network("23.246.0.0/18")} and ds.v6 == {ip_network("2001:db8::1/128")}
    assert m.asns() == [2906]
    with_asn = PolicyMatcher.from_config(CFG, asn_prefixes=lambda n: ["198.38.96.0/19"])
    assert ip_network("198.38.96.0/19") in with_asn.static_sets()[0].v4
    assert m.bases(2) == ["netflix.com", "nflxvideo.net"] and m.bases(1) == []


def test_bad_policy_entries_are_reported() -> None:
    cfg = _config(
        {"name": "p", "targets": ["jp"], "domains": ["ok.example", "asn:x", "bad domain"]}
    )
    m = PolicyMatcher.from_config(cfg)
    assert [e.index for e in m.policies[0].errors] == [1, 2]
    assert m.match("ok.example") == 1
    res = commands.check_config(cfg)
    assert res.code == 1 and "rule 2: error: invalid ASN" in res.output


# --- ASN cache -----------------------------------------------------------


def _ripe(*prefixes: str) -> bytes:
    return json.dumps({"data": {"prefixes": [{"prefix": p} for p in prefixes]}}).encode()


def test_asn_cache(tmp_path: Path) -> None:
    now = [1000.0]
    calls: list[str] = []
    answer = [_ripe("1.2.3.0/24", "2001:db8::/32")]

    def fetch(url: str) -> bytes:
        calls.append(url)
        return answer[0]

    c = AsnCache(tmp_path, max_age=100, refresh_after=50, fetch=fetch, clock=lambda: now[0])
    assert c.cached(2906) == [] and c.stale(2906)
    assert c.prefixes(2906).prefixes == ("1.2.3.0/24", "2001:db8::/32")
    assert calls == [c.url.format(asn=2906)] and "AS2906" in calls[0]
    assert c.prefixes(2906).prefixes and len(calls) == 1  # fresh: no fetch
    now[0] += 60  # due, still usable
    answer[0] = b"not json"
    due = c.prefixes(2906)
    assert due.prefixes == ("1.2.3.0/24", "2001:db8::/32") and due.error
    now[0] += 60  # past max_age: a failed refresh does not fall back to it
    with pytest.raises(AsnError):
        c.prefixes(2906)
    with pytest.raises(AsnError):
        c.prefixes(13335)
    assert c.cached(2906) == ["1.2.3.0/24", "2001:db8::/32"]  # display only
    with pytest.raises(AsnError, match="stale"):
        c.usable(2906)


def test_parse_ripe_empty() -> None:
    with pytest.raises(AsnError):
        parse_ripe(_ripe())


# --- rules commands ------------------------------------------------------


def test_check_command() -> None:
    res = commands.check("example.com\nbad domain\nsession:s.example\n", path="x.rules")
    assert res.code == 1
    assert "x.rules:2: error:" in res.output
    assert "not supported by pyvpn yet: session:s.example" in res.output
    assert commands.check("example.com\n").code == 0


def test_explain_commands() -> None:
    res = commands.explain_rules(["netflix.com", "!=ads.netflix.com"], ["WWW.netflix.com."])
    assert res.code == 0 and "route by netflix.com" in res.output
    assert commands.explain_rules(["netflix.com"], ["x.test"]).code == 1
    res = commands.explain_config(CFG, ["ads.netflix.com"])
    assert (
        res.code == 0
        and "policy 'office'" in res.output
        and "skipped policy 'stream'" in res.output
    )
    assert "no policy" in commands.explain_config(CFG, ["x.test"]).output


def test_import_and_export() -> None:
    res, f = commands.import_rules("||disneyplus.com^\n0.0.0.0 ads.example\nasn:AS1\n")
    assert res.code == 0
    assert res.output == "# snake rules v1\n\ndisneyplus.com\n=ads.example\n\nasn:1\n"
    assert commands.policy_entries(f) == ("disneyplus.com", "=ads.example", "asn:1")
    assert "converted 2 lines" in commands.import_notes("||a.example^\n||b.example^\n")
    out = commands.export_policy(CFG.policies[1]).output
    assert out.startswith("# snake rules v1\n@name stream\n\nnetflix.com\n")
    assert "asn:2906\n" in out and "cidr:23.246.0.0/18\ncidr:2001:db8::1\n" in out


def test_asn_cache_writes_atomically(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    c = AsnCache(tmp_path, fetch=lambda url: _ripe("1.2.3.0/24"))
    synced: list[int] = []
    real_fsync = os.fsync

    def fsync(fd: int) -> None:
        synced.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    c.prefixes(1, force=True)
    c.prefixes(1, force=True)
    assert c.cached(1) == ["1.2.3.0/24"] and len(synced) == 2
    name = c._path(1).name
    assert [p.name for p in tmp_path.iterdir()] == [name]  # no temp files left

    def fail(src: object, dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError):
        c.prefixes(1, force=True)
    assert [p.name for p in tmp_path.iterdir()] == [name]
    assert c.cached(1) == ["1.2.3.0/24"]


def test_scoped_matcher_only_considers_the_asking_policys_apps() -> None:
    cfg = _config(
        {"name": "firefox", "targets": ["jp"], "apps": [{"name": "firefox"}],
         "domains": ["office.example"]},
        {"name": "chrome", "targets": ["jp"], "apps": [{"name": "chrome"}],
         "domains": ["office.example"]},
        {"name": "all", "targets": ["jp"], "domains": ["shared.example"]},
    )  # fmt: skip
    m = build_matcher(cfg)
    assert m.match("office.example") == 1  # unscoped: first policy wins
    assert m.scoped(2).match("office.example") == 2  # Chrome's stub
    assert m.scoped(1).match("office.example") == 1
    assert m.scoped(2).match("shared.example") == 3  # domain-only policies apply to all


def test_malformed_cached_asn_prefix_is_refused() -> None:
    cfg = _config({"name": "asn-only", "targets": ["jp"], "domains": ["asn:AS2906"]})
    problems = PolicyMatcher.from_config(cfg, asn_prefixes=lambda n: ["not-a-network"]).problems()
    assert problems == [
        "policy 'asn-only': asn:2906 cached prefix 'not-a-network' is not a network"
    ]


def test_rules_check_reports_asn_cache_problems() -> None:
    cfg = _config({"name": "asn-only", "targets": ["jp"], "domains": ["asn:AS2906"]})
    res = commands.check_config(cfg)
    assert res.code == 1 and "asn:2906 needs the ASN cache" in res.output
    res = commands.check_config(cfg, asn_prefixes=lambda n: [])
    assert res.code == 1 and "asn:2906 has no cached prefixes" in res.output
    assert commands.check_config(cfg, asn_prefixes=lambda n: ["198.38.96.0/19"]).code == 0


def test_scoped_matcher_skips_policies_that_may_exclude_the_asking_app() -> None:
    cfg = _config(
        {"name": "all-but-chrome", "targets": ["jp"], "exclude_apps": [{"name": "chrome"}],
         "domains": ["office.example"]},
        {"name": "chrome", "targets": ["jp"], "on_down": "block", "apps": [{"name": "chrome"}],
         "domains": ["office.example"]},
    )  # fmt: skip
    m = build_matcher(cfg)
    assert m.scoped(2).match("office.example") == 2  # Chrome's lookup picks Chrome's policy
    assert m.scoped(1).match("office.example") == 1
