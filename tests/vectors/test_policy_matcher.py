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


def test_runtime_rejects_unenforced_drop_rules() -> None:
    cfg = _config(
        {"name": "a", "targets": ["jp"], "domains": ["drop:ads.tv"]},
        {"name": "b", "targets": ["jp"], "domains": ["ads.tv"]},
    )
    # Leniently built, the drop claims the name and policy "b" never sees it.
    assert PolicyMatcher.from_config(cfg).match("x.ads.tv") is None
    with pytest.raises(RuleConfigError, match=r"policy 'a': drop: .*drop:ads\.tv"):
        build_matcher(cfg)


def test_runtime_asn_rules_use_the_cache(tmp_path: Path) -> None:
    cfg = _config({"name": "asn-only", "targets": ["jp"], "domains": ["asn:AS2906"]})
    with pytest.raises(RuleConfigError, match="asn:2906 needs the ASN cache"):
        build_matcher(cfg)
    cache = AsnCache(tmp_path, fetch=lambda url: _ripe("198.38.96.0/19"))
    factory = matcher_factory(cache)
    with pytest.raises(RuleConfigError, match="asn:2906 has no cached prefixes"):
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
    assert m.policies[0].unsupported() == ["drop:ads.tv"]


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

    c = AsnCache(tmp_path, max_age=100, fetch=fetch, clock=lambda: now[0])
    assert c.cached(2906) == [] and c.stale(2906)
    assert c.prefixes(2906).prefixes == ("1.2.3.0/24", "2001:db8::/32")
    assert calls == [c.url.format(asn=2906)] and "AS2906" in calls[0]
    assert c.prefixes(2906).prefixes and len(calls) == 1  # fresh: no fetch
    now[0] += 200
    answer[0] = b"not json"
    stale = c.prefixes(2906)
    assert stale.prefixes == ("1.2.3.0/24", "2001:db8::/32") and stale.error
    with pytest.raises(AsnError):
        c.prefixes(13335)
    assert c.cached(2906) == ["1.2.3.0/24", "2001:db8::/32"]


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
