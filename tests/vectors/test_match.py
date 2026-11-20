"""snake internal/match/match_test.go, index_test.go, drop_test.go."""

from __future__ import annotations

import pytest

from pyvpn.match import Kind, Result, RuleError, RuleSet, normalize, parse

PARSE_CASES = [
    ("Netflix.com", Kind.SUFFIX, "netflix.com",
     ["netflix.com", "www.netflix.com", "a.b.netflix.com"], ["notnetflix.com", "netflix.com.evil"]),
    ("https://www.netflix.com/browse", Kind.SUFFIX, "www.netflix.com",
     ["www.netflix.com"], ["netflix.com"]),
    (".example.com", Kind.SUBDOMAINS, "example.com",
     ["a.example.com", "a.b.example.com"], ["example.com"]),
    ("=example.com", Kind.EXACT, "example.com", ["example.com"], ["a.example.com"]),
    ("*.example.com", Kind.GLOB, "example.com",
     ["a.example.com", "x-1.example.com"], ["a.b.example.com", "example.com"]),
    ("**.example.com", Kind.GLOB, "example.com",
     ["a.example.com", "a.b.example.com"], ["example.com", "aexample.com"]),
    ("api-?.*.disney.com", Kind.GLOB, "disney.com",
     ["api-1.x.disney.com"], ["api-12.x.disney.com", "api-1.disney.com"]),
    ("ipv4-*.oca.nflxvideo.net", Kind.GLOB, "oca.nflxvideo.net",
     ["ipv4-c001-lhr.oca.nflxvideo.net"], ["ipv6-c001.oca.nflxvideo.net"]),
    ("~nflx", Kind.KEYWORD, "", ["nflxvideo.net", "a.nflximg.com"], ["netflix.com"]),
    (r"/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/", Kind.REGEX, "oca.nflxvideo.net",
     ["ipv4-c123-lhr001-ix.oca.nflxvideo.net"], ["ipv4-cx-lhr.oca.nflxvideo.net"]),
    ("re:disney", Kind.REGEX, "", ["disneyplus.com", "x.disney.api.edge"], ["dssott.com"]),
    (r"/(?:^|\.)bamgrid\.com$/", Kind.REGEX, "",
     ["bamgrid.com", "x.bamgrid.com"], ["xbamgrid.com"]),
    ("*.net", Kind.GLOB, "", ["a.net"], []),
    ("example.com # streaming", Kind.SUFFIX, "example.com", ["a.example.com"], []),
]  # fmt: skip


@pytest.mark.parametrize(("rule", "kind", "base", "yes", "no"), PARSE_CASES)
def test_parse_and_match(rule: str, kind: Kind, base: str, yes: list[str], no: list[str]) -> None:
    p = parse(rule)
    assert (p.kind, p.base) == (kind, base)
    for n in yes:
        assert p.match(n), n
    for n in no:
        assert not p.match(n), n


@pytest.mark.parametrize(
    "rule",
    ["", "bad domain.com", "/unterminated", "/a(b/", "~", "=", "a***.com", "-bad-.com", ".", "!",
     "com", ".net"],
)  # fmt: skip
def test_parse_errors(rule: str) -> None:
    with pytest.raises(RuleError):
        parse(rule)


def test_set() -> None:
    s, errs = RuleSet.compile(
        ["# comment", "", "netflix.com", "**.nflxvideo.net", "!=ads.netflix.com", "bad rule"]
    )
    assert len(errs) == 1 and errs[0].index == 5
    r = s.match_any("www.netflix.com")
    assert r.matched and r.rule == "netflix.com"
    r = s.match_any("ads.netflix.com")
    assert not r.matched and r.excluded == "!=ads.netflix.com"
    # CNAME chain: query name unknown, target matches.
    r = s.match_any("movies.partner.tv", "abc.lhr.nflxvideo.net")
    assert r.matched and r.name == "abc.lhr.nflxvideo.net"
    # exclusions must disable the suffix-only fast path
    assert s.native_suffixes() is None and s.needs_inspector()
    plain, _ = RuleSet.compile(["netflix.com", "nflxvideo.net"])
    assert len(plain.native_suffixes() or []) == 2 and not plain.needs_inspector()
    assert s.bases() == ["netflix.com", "nflxvideo.net"]


def test_regex_error_text() -> None:
    with pytest.raises(RuleError) as e:
        parse("/bad(regex/")
    assert "(?i)" not in str(e.value)


def test_regex_rejects_non_re2() -> None:
    # Python's re accepts these, RE2 (snake) does not.
    for bad in [r"/(?=a)b/", r"/(a)\1/", r"/(?<!x)y/", r"/(?>ab)c/", r"/a*+b/", r"/(a|b)++/"]:
        with pytest.raises(RuleError):
            parse(bad)


# --- index_test.go -------------------------------------------------------


def _linear(s: RuleSet, *names: str) -> Result:
    """The reference: first name, earliest rule."""
    for n in names:
        for p in s.exclude:
            if p.match(n):
                return Result(excluded=p.raw, name=n)
    for n in names:
        for p in s.include:
            if p.match(n):
                return Result(matched=True, name=n, rule=p.raw)
    return Result()


INDEX_RULES = [
    "~flix", "netflix.com", ".netflix.com", "=www.netflix.com", "*.nflxvideo.net",
    "**.nflxvideo.net", "nflxvideo.net", r"/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/", "=example.org",
    ".example.org", "example.org", "cdn-?.example.net", "com", "!=ads.netflix.com",
    "!.tracking.example.org", "!~adserver",
]  # fmt: skip
INDEX_NAMES = [
    "netflix.com", "www.netflix.com", "a.b.netflix.com", "ads.netflix.com", "x.ads.netflix.com",
    "nflxvideo.net", "a.nflxvideo.net", "a.b.nflxvideo.net", "ipv4-c042-lhr001.oca.nflxvideo.net",
    "example.org", "www.example.org", "t.tracking.example.org", "cdn-1.example.net",
    "cdn-12.example.net", "anything.com", "com", "adserver.example.org", "unrelated.test", "",
    "netflix.com.evil.test", "xnetflix.com",
]  # fmt: skip


def test_index_matches_linear() -> None:
    s = RuleSet.must_compile(INDEX_RULES)
    for a in INDEX_NAMES:
        assert s.match_any(a) == _linear(s, a), a
        for b in INDEX_NAMES[:6]:
            assert s.match_any(a, b) == _linear(s, a, b), (a, b)
    # rule order decides which rule is reported
    for i in range(len(INDEX_RULES)):
        rot = RuleSet.must_compile(INDEX_RULES[i:] + INDEX_RULES[:i])
        for n in INDEX_NAMES:
            assert rot.match_any(n) == _linear(rot, n), (i, n)


# --- drop_test.go --------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("DROP:Ads.Example.com", "drop:ads.example.com"),
        ("drop: https://x.example/a", "drop:x.example"),
        ("drop:ASN:AS1234", "drop:asn:1234"),
        ("drop:CIDR: 10.0.0.0/8", "drop:cidr:10.0.0.0/8"),
        (r"drop:/^AD-\d+\.x$/", r"drop:/^AD-\d+\.x$/"),
        ("drop:ads.example.com # c", "drop:ads.example.com"),
    ],
)
def test_drop_normalize(raw: str, want: str) -> None:
    assert normalize(raw) == want


@pytest.mark.parametrize(
    "bad",
    ["drop:", "!drop:ads.example.com", "drop:!ads.example.com", "drop:drop:a.example",
     "drop:asn:x", "drop:cidr:1.2.3", "drop:com"],
)  # fmt: skip
def test_drop_errors(bad: str) -> None:
    with pytest.raises(RuleError):
        parse(bad)


def test_drop_rules() -> None:
    p = parse("drop:asn:AS1234")
    assert p.kind is Kind.ASN and p.value == "1234" and p.drop
    p = parse("drop:ip:192.0.2.9")
    assert p.kind is Kind.CIDR and p.value == "192.0.2.9"

    s = RuleSet.must_compile(
        ["example.com", "**.cdn.example", "drop:ads.example.com", "drop:**.tracker.example",
         "drop:~doubleclk", "!=ok.ads.example.com", "drop:asn:1234", "drop:cidr:198.51.100.0/24",
         "drop:cidr:203.0.113.7"]
    )  # fmt: skip
    assert (len(s.include), len(s.drop), len(s.exclude)) == (2, 3, 1)
    assert (len(s.drop_asns), len(s.drop_cidrs)) == (1, 2) and s.has_drops()
    cases = [
        (["www.example.com"], True, False, "example.com"),
        (["ads.example.com"], True, True, "drop:ads.example.com"),  # drop beats the include
        (["x.ads.example.com"], True, True, "drop:ads.example.com"),  # subdomain
        (["ok.ads.example.com"], False, False, ""),  # ! exempts from drop
        (["a.b.tracker.example"], True, True, "drop:**.tracker.example"),
        (["www.example.com", "ad.doubleclk.net"], True, True, "drop:~doubleclk"),  # via CNAME
        (["unrelated.test"], False, False, ""),
    ]
    for names, matched, drop, rule in cases:
        r = s.match_any(*names)
        assert (r.matched, r.drop, r.rule) == (matched, drop, rule), names
    # with exclusions a suffix-only resolver must not drop by itself
    assert s.drop_suffixes(False) is None
    assert s.drop_suffixes(True) == ["ads.example.com"]
    assert s.needs_inspector()  # drop wildcards need the inspector
    plain = RuleSet.must_compile(["drop:ads.example.com"])
    assert not plain.needs_inspector()
    assert plain.drop_suffixes(False) == ["ads.example.com"]
    assert plain.native_suffixes() == []
