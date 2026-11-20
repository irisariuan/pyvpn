"""snake internal/rulefile/rulefile_test.go."""

from __future__ import annotations

from pyvpn.rulefile import HEADER, format_file, parse_text

SAMPLE = r"""# snake rules v1
@name Netflix
@description Netflix  streaming
@source https://example.com/netflix.rules

# core
netflix.com
NFLXVIDEO.net.
**.nflxvideo.net
/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/
~nflxso
!=ads.netflix.com
netflix.com
asn:AS2906
ASN: 40027
asn:2906
cidr:23.246.0.0/18
ip:198.38.96.1 # single host
"""


def test_parse_and_format() -> None:
    r = parse_text(SAMPLE)
    assert r.errors == []
    f = r.file
    assert (f.name, f.description, f.source) == (
        "Netflix",
        "Netflix  streaming",
        "https://example.com/netflix.rules",
    )
    assert f.domains == [
        "# core",
        "netflix.com",
        "nflxvideo.net",
        "**.nflxvideo.net",
        r"/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/",
        "~nflxso",
        "!=ads.netflix.com",
    ]
    assert f.asns == [2906, 40027]
    assert len(f.cidrs) == 2 and f.cidrs[1] == "198.38.96.1"
    # Round trip: format then parse yields the same file.
    out = format_file(f)
    assert out.startswith(HEADER + "\n@name Netflix\n@description Netflix streaming\n")
    r2 = parse_text(out)
    assert format_file(r2.file) == out and r2.errors == []


def test_errors_have_line_numbers() -> None:
    r = parse_text("netflix.com\n\nbad domain\nasn:xyz\ncidr:300.1.1.1\n/bad(/\n@colour blue\n")
    assert [e.line for e in r.errors] == [3, 4, 5, 6]
    assert [w.line for w in r.warnings] == [7]


def test_convert() -> None:
    text = (
        "! Title: some list\n||disneyplus.com^\n||bamgrid.com^$third-party\n"
        "0.0.0.0 ads.example.com tracker.example.com # x\n127.0.0.1 localhost\n"
        "server=/dssott.com/starott.com/1.1.1.1\nipset=/hulu.com/SOMESET\n!=keep.example.com\n"
    )
    r = parse_text(text, convert=True)
    assert r.errors == []
    assert r.file.domains == [
        "disneyplus.com",
        "bamgrid.com",
        "=ads.example.com",
        "=tracker.example.com",
        "dssott.com",
        "starott.com",
        "hulu.com",
        "!=keep.example.com",
    ]
    assert r.converted == 7
    # Without convert, foreign lines are errors.
    assert len(parse_text("||disneyplus.com^\n").errors) == 1


def test_drop_rules_in_files() -> None:
    r = parse_text(
        "@name Block\nnetflix.com\nDROP:ads.netflix.com\ndrop:asn:AS1234 # isp ads\n"
        "drop:cidr:198.51.100.0/24\nasn:2906\n"
    )
    assert r.errors == []
    assert r.file.domains == [
        "netflix.com",
        "drop:ads.netflix.com",
        "drop:asn:1234",
        "drop:cidr:198.51.100.0/24",
    ]
    assert r.file.asns == [2906]  # include ASNs stay separate
    out = format_file(r.file)
    r2 = parse_text(out)
    assert format_file(r2.file) == out and r2.errors == []
    bad = parse_text("drop:asn:nope\n")
    assert len(bad.errors) == 1 and bad.errors[0].line == 1


def test_legacy_route_form() -> None:
    typed = parse_text("route:a.example;if:b.example\n")
    assert len(typed.errors) == 1 and "if:b.example;then:route:a.example" in typed.errors[0].message
    imported = parse_text("route:a.example;if:b.example\n", convert=True)
    assert imported.errors == [] and imported.converted == 1
    assert imported.file.domains == ["if:b.example;then:route:a.example"]


def test_multiline_route_is_one_entry() -> None:
    r = parse_text("if:a.example;\nthen:route:or:(\n  b.example,\n  c.example\n)\nd.example\n")
    assert r.errors == []
    assert len(r.file.domains) == 2 and r.file.domains[1] == "d.example"
    assert r.file.domains[0].startswith("if:a.example;\nthen:route:or:(")


def test_bom_and_crlf() -> None:
    r = parse_text("﻿@name X\r\nexample.com\r\n")
    assert r.file.name == "X" and r.file.domains == ["example.com"]
