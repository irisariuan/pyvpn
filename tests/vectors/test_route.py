"""snake internal/match/route_test.go and session_test.go."""

from __future__ import annotations

import pytest

from pyvpn.match import (
    Action,
    Expr,
    RuleError,
    RuleSet,
    group,
    is_legacy_route,
    is_route,
    parse,
    parse_route,
)
from pyvpn.match.opts import SET_OFF, SET_ON, SET_TOGGLE, SHARE_GLOBAL

ROUTE_LINES = [
    "netflix.com",
    "route[ttl=5m;onlookup=1]:or:(",
    "  **.akamaized.net,   # CDN",
    r"  /^ipv4-c\d+\.oca\.example$/",
    ");",
    "if:or:(disneyplus.com, and:(hulu.com, not:=help.hulu.com))",
    "# a comment",
    "route:(or:(a.example, b.example), not:=bad.a.example, and:(not:~ads, ~cdn)); "
    "if:=trigger.example",
    "session[ttl=90;onlookup=0]:x.example",
    "plain.example",
]


def _kind(s: RuleSet, name: str) -> str:
    r = s.match_any(name)
    if r.excluded:
        return "exclude"
    if r.cond:
        return "cond"
    if r.drop:
        return "drop"
    if r.route:
        return "route"
    if r.session:
        return "session"
    if r.matched:
        return "include"
    return "none"


def test_route_rules() -> None:
    g = group(ROUTE_LINES)
    assert len(g) == 6 and g[1].first == 1 and g[3].first == 7
    assert g[1].text.endswith("if:or:(disneyplus.com, and:(hulu.com, not:=help.hulu.com))")
    s, errs = RuleSet.compile(ROUTE_LINES)
    assert errs == []
    assert len(s.routes) == 2 and len(s.session) == 1 and s.has_sessions() and s.needs_inspector()
    r0 = s.routes[0]
    # The old route:...;if:... form is read as if:...;then:route:....
    o = r0.then.opts
    assert o.ttl == 300 and o.onlookup and r0.then.kind == "route"
    assert r0.raw == (
        "if:or:(disneyplus.com, and:(hulu.com, not:=help.hulu.com));\n"
        r"then:route[ttl=5m;onlookup=1]:or:(**.akamaized.net,/^ipv4-c\d+\.oca\.example$/)"
    )
    assert s.routes[1].raw == (
        "if:=trigger.example;then:route:(or:(a.example, b.example), not:=bad.a.example, "
        "and:(not:~ads, ~cdn))"
    )
    assert s.session[0].opts.ttl == 90 and s.session[0].raw == "session[ttl=90s]:x.example"
    for name, want in [
        ("www.disneyplus.com", "cond"),  # if: atoms are routed for everyone
        ("www.hulu.com", "cond"),
        ("help.hulu.com", "cond"),  # hulu.com matches; the not: only matters for the condition
        ("trigger.example", "cond"),
        ("e1.akamaized.net", "route"),
        ("ipv4-c12.oca.example", "route"),
        ("a.example", "none"),  # and: also needs ~cdn
        ("cdn.a.example", "route"),
        ("bad.a.example", "none"),  # not:=bad.a.example
        ("ads.cdn.b.example", "none"),  # and:(not:~ads, ~cdn)
        ("cdn.b.example", "route"),
        ("b.example", "none"),  # ~cdn missing
        ("www.netflix.com", "include"),
        ("x.example", "session"),
    ]:
        assert _kind(s, name) == want, name
    # Cond hits name the atoms the addresses count for.
    r = s.match_any("www.hulu.com")
    assert len(r.cond) == 1 and r.cond[0].rule == r0.raw and r.cond[0].atom == 2

    # The condition: atoms 1 (disneyplus), 2 (hulu), 3 (help.hulu, negated).
    def on(*ids: int) -> object:
        return lambda a: a.id in ids

    assert r0.if_ is not None
    for ids, want_b in [((1,), True), ((2,), True), ((2, 3), False), ((), False), ((1, 3), True)]:
        assert r0.if_.eval(on(*ids)) is want_b, ids  # type: ignore[arg-type]
    b = ",".join(s.bases())
    assert "akamaized.net" in b and "disneyplus.com" in b


@pytest.mark.parametrize(
    ("want", "rule"),
    [
        ("expected , or )", "route:or:(a.com, b.com;if:c.com"),
        ("needs ( ... )", "route:or:a.com"),
        ("unexpected", "route:a.com;c.com"),
        ("only domain rules", "route:drop:a.com"),
        ("not negated", "route:a.com;if:not:b.com"),
        ("unknown option", "route[foo=1]:a.com"),
        ("between 10s", "session[ttl=1]:a.com"),
        ("onlookup must be", "session[onlookup=2]:a.com"),
        ("unterminated", "route:/abc;if:b.com"),
    ],
)
def test_route_errors(want: str, rule: str) -> None:
    with pytest.raises(RuleError, match=None) as e:
        if is_route(rule):
            parse_route(rule)
        else:
            parse(rule)
    assert want in str(e.value)


def test_route_error_reports_first_line() -> None:
    _, errs = RuleSet.compile(["a.com", "route:or:(", "b.com,", "drop:c.com", ")"])
    assert len(errs) == 1 and errs[0].index == 1


def test_share_option() -> None:
    p = parse(
        "session[share=kids,share=10.6.0.2;share=AA-BB-CC-00-00-31,share=group:kids,"
        "share=10.8.0.5/24]:x.example"
    )
    assert p.opts.share == ("kids", "10.6.0.2", "aa:bb:cc:00:00:31", "10.8.0.0/24")
    assert p.raw == (
        "session[share=kids;share=10.6.0.2;share=aa:bb:cc:00:00:31;share=10.8.0.0/24]:x.example"
    )
    r = parse_route("route[share=global]:a.example;if:b.example")
    assert r.then.opts.share == (SHARE_GLOBAL,)
    with pytest.raises(RuleError):
        parse("session[share=bad/name]:x.example")


def test_drop_session_rules() -> None:
    s, errs = RuleSet.compile(
        ["drop[share=kids;ttl=5m]:ads.example.com", "drop:tracker.example", "example.com"]
    )
    assert errs == []
    assert s.has_drop_sessions() and s.drop[0].raw == "drop[ttl=5m;share=kids]:ads.example.com"
    r = s.match_any("x.ads.example.com")
    st = s.steps_for("x.ads.example.com")
    assert r.route and len(st) == 1
    assert st[0].drop is not None and st[0].drop.opts.ttl == 300 and len(st[0].drop.opts.share) == 1
    r = s.match_any("tracker.example")
    assert r.drop and r.opts.is_zero()
    # drop sessions are per device
    assert s.drop_suffixes(False) == ["tracker.example"]
    assert s.needs_inspector()
    for bad in ["drop[share=kids]:asn:1234", "drop[ttl=2]:a.com", "!drop[ttl=5m]:a.com"]:
        with pytest.raises(RuleError):
            parse(bad)


IF_LINES = [
    "if:netflix.com;",
    "then:route[ttl=10m]:or:(**.akamaized.net, **.nflxvideo.net);",
    "else:drop:**.nflxvideo.net;",
    "finally:route:=help.netflix.com",
    "if:a.example",
    "then:drop[share=kids]:b.example",
    "finally:route:(c.example, not:=x.c.example)",
    "plain.example",
]


def _act(a: Action | None) -> str:
    return "-" if a is None else a.kind


def test_if_then_else() -> None:
    g = group(IF_LINES)
    assert len(g) == 3 and g[1].first == 4
    s, errs = RuleSet.compile(IF_LINES)
    assert errs == []
    r = s.routes[0]
    assert r.then.kind == "route" and r.then.opts.ttl == 600
    assert _act(r.else_) == "drop" and _act(r.finally_) == "route"
    assert s.has_drop_sessions() and s.has_conds()
    for name, cond, want in [
        ("e1.akamaized.net", True, "route"),
        ("e1.akamaized.net", False, "-"),
        ("x.nflxvideo.net", True, "route"),
        ("x.nflxvideo.net", False, "drop"),
        ("help.netflix.com", True, "route"),  # finally: either way
        ("help.netflix.com", False, "route"),
    ]:
        assert _act(r.pick(cond, name)) == want, (name, cond)
    # Names in the condition are routed for everyone; branch names go to the engine.
    assert s.match_any("www.netflix.com").cond
    m = s.match_any("x.nflxvideo.net")
    assert m.route and m.rule == r.raw
    r2 = s.routes[1]
    assert r2.else_ is None
    assert _act(r2.pick(False, "b.example")) == "-"
    assert _act(r2.pick(True, "b.example")) == "drop"
    assert _act(r2.pick(False, "c.example")) == "route"
    assert r2.pick(True, "x.c.example") is None
    b = ",".join(s.bases())
    assert "b.example" not in b and "c.example" in b  # drop branches need no tunnel DNS


@pytest.mark.parametrize(
    ("want", "rule"),
    [
        ("expected ;then:", "if:a.com"),
        ("needs an action", "if:a.com;then:b.com"),
        ("order if:", "if:a.com;then:route:b.com;finally:route:c.com;else:drop:d.com"),
        ("only domain rules", "if:a.com;then:route:drop:b.com"),
        ("not negated", "if:not:a.com;then:route:b.com"),
        ("unknown option", "if:a.com;then:drop[x=1]:b.com"),
        ("expected ;then:ACTION", "if:a.com;else:route:b.com"),
    ],
)
def test_if_errors(want: str, rule: str) -> None:
    with pytest.raises(RuleError) as e:
        parse_route(rule)
    assert want in str(e.value)


def test_is_legacy_route() -> None:
    assert is_legacy_route("route:a.com;if:b.com")
    assert not is_legacy_route("route:a.com")
    assert not is_legacy_route("if:b.com;then:route:a.com")


def test_set_option() -> None:
    r = parse_route(
        "if:a.example;then:route[ttl=-1;set=on]:b.example;else:drop[ttl=-5m,set=toggle]:b.example"
    )
    assert r.else_ is not None
    assert r.then.opts.permanent() and r.then.opts.set_mode() == SET_ON
    assert r.else_.opts.set_mode() == SET_TOGGLE
    p = parse("drop[ttl=-1;set=0;share=kids]:ads.example")
    assert p.raw == "drop[ttl=-1;set=0;share=kids]:ads.example" and p.opts.set_mode() == SET_OFF
    # set=1 is the default
    assert parse("drop[set=1;ttl=-1]:x.example").raw == "drop[ttl=-1]:x.example"


@pytest.mark.parametrize(
    ("want", "rule"),
    [
        ("needs a negative ttl", "drop[set=0]:a.example"),
        ("onlookup has no effect", "drop[ttl=-1;onlookup=1]:a.example"),
        ("set must be", "drop[ttl=-1;set=2]:a.example"),
        ("for route and drop", "session[ttl=-1]:a.example"),
        ("seconds or a duration", "drop[ttl=-x]:a.example"),
    ],
)
def test_set_option_errors(want: str, rule: str) -> None:
    with pytest.raises(RuleError) as e:
        parse(rule)
    assert want in str(e.value)


def test_steps_order() -> None:
    """Route/drop rules matching one lookup apply top to bottom."""
    s, errs = RuleSet.compile(
        [
            "drop[ttl=-1]:=x.both.example",
            "plain.example",
            "route[ttl=-1]:**.both.example",
            "if:t.example;then:drop:**.both.example",
            "drop:blocked.example",
        ]
    )
    assert errs == []
    assert [st.raw for st in s.steps_for("x.both.example")] == [
        "drop[ttl=-1]:=x.both.example",
        "route[ttl=-1]:**.both.example",
        "if:t.example;then:drop:**.both.example",
    ]
    r = s.match_any("x.both.example")
    assert r.route and r.rule == "drop[ttl=-1]:=x.both.example"
    r = s.match_any("y.both.example")
    assert r.route and r.rule == "route[ttl=-1]:**.both.example"
    r = s.match_any("blocked.example")
    assert r.drop and not r.route


# --- session_test.go -----------------------------------------------------


def test_session_rules() -> None:
    s, errs = RuleSet.compile(
        ["netflix.com", "SESSION:**.Akamaized.net", "session:~nflxso", "drop:ads.akamaized.net",
         "!=ok.akamaized.net"]
    )  # fmt: skip
    assert errs == []
    assert s.has_sessions() and len(s.session) == 2
    assert s.session[0].raw == "session:**.akamaized.net"
    for name, want in [
        ("a1.akamaized.net", "session"),
        ("www.netflix.com", "include"),
        ("x.nflxso.net", "session"),
        ("ads.akamaized.net", "drop"),  # drop beats session
        ("ok.akamaized.net", "exclude"),  # ! beats session
        ("example.org", "none"),
    ]:
        assert _kind(s, name) == want, name
    # Session beats a plain rule for the same name.
    s2 = RuleSet.must_compile(["akamaized.net", "session:**.akamaized.net"])
    assert s2.match_any("a.akamaized.net").session
    assert s.needs_inspector()
    assert "akamaized.net" in ",".join(s.bases())
    assert not any("akamaized" in n for n in s.native_suffixes() or [])
    for bad in ["session:", "!session:a.com", "session:asn:1", "session:drop:a.com",
                "drop:session:a.com", "session:!a.com"]:  # fmt: skip
        with pytest.raises(RuleError):
            parse(bad)


def test_expr_ids_are_numbered() -> None:
    r = parse_route("if:or:(a.example, not:b.example);then:route:c.example")
    assert r.if_ is not None
    assert [a.id for a in r.if_.all()] == [1, 2]
    assert [a.id for a in r.if_.positive()] == [1]
    assert isinstance(r.if_, Expr)
