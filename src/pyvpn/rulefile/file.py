"""Read and write snake rule files (``.rules``). Port of snake ``internal/rulefile``.

A rule file is UTF-8 text, one entry per line::

    # snake rules v1                     comment
    @name Netflix                        directive: list name
    @description Netflix streaming       directive: free text
    @source https://example.com/x.rules  directive: where updates come from
    netflix.com                          domain rule (see pyvpn.match)
    **.nflxvideo.net
    !=ads.netflix.com
    asn:2906                             autonomous system (AS prefix optional)
    cidr:23.246.0.0/18                   address range or single IP (ip: also accepted)

On import (``convert=True``) lines from common list formats are converted,
and the old ``route:EXPR;if:COND`` form becomes ``if:COND;then:route:EXPR``:
AdBlock/AdGuard ``||example.com^``, hosts files ``0.0.0.0 example.com``, and
dnsmasq ``server=/a/b/...`` / ``ipset=/a/b/...`` / ``address=/a/...`` lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pyvpn.match import (
    RuleError,
    convert_legacy,
    group,
    is_route,
    normalize,
    parse,
    parse_asn,
    parse_route,
)
from pyvpn.match.opts import canonical_cidr, canonical_ip

HEADER = "# snake rules v1"
"""The first line written on export (shared with snake, so files move both ways)."""


@dataclass
class RuleFile:
    name: str = ""
    description: str = ""
    source: str = ""
    domains: list[str] = field(default_factory=list)  # domain rules and comments, in order
    asns: list[int] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Issue:
    """A problem on one line (1-based)."""

    line: int
    text: str
    message: str


@dataclass
class ParseResult:
    file: RuleFile = field(default_factory=RuleFile)
    errors: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    converted: int = 0  # lines converted from other formats


_HOSTS_RE = re.compile(r"^(0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)")
_ABP_RE = re.compile(r"^\|\|([a-z0-9.\-_*]+)\^(\$.*)?$")
_DNSMASQ_RE = re.compile(r"^(server|ipset|nftset|address|local)=/(.+)/")
_HOSTS_SKIP = {
    "localhost",
    "localhost.localdomain",
    "localhost4",
    "localhost4.localdomain4",
    "localhost6",
    "localhost6.localdomain6",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "broadcasthost",
    "local",
}


def _has_prefix(s: str, p: str) -> bool:
    return s[: len(p)].lower() == p


def _strip_hash(s: str) -> str:
    return s.split("#", 1)[0]


def _valid_cidr(v: str) -> bool:
    return canonical_cidr(v) is not None or canonical_ip(v) is not None


def parse_text(text: str, convert: bool = False) -> ParseResult:
    """Read rule-file text. With ``convert``, foreign list formats are
    translated; otherwise they are reported as errors."""
    r = ParseResult()
    f = r.file
    text = text.removeprefix("﻿").replace("\r\n", "\n")
    for lg in group(text.split("\n")):
        n, raw = lg.first + 1, lg.text
        line = raw.strip()
        if not line:
            continue

        def issue(msg: str, n: int = n, raw: str = raw) -> Issue:
            return Issue(n, raw, msg)

        if is_route(line):
            conv = convert_legacy(raw)
            if conv is not None:
                # The old route:EXPR;if:COND form: converted on import,
                # rejected (with the new form) in typed rules.
                if not convert:
                    new = conv.replace("\n", " ")
                    r.errors.append(
                        issue(f"the route:...;if:... form was replaced; write it as: {new}")
                    )
                    continue
                r.converted += 1
            try:
                parse_route(line)
            except RuleError as e:
                r.errors.append(issue(str(e)))
                continue
            f.domains.append(normalize(line))
            continue
        if line.startswith("#"):
            if line != HEADER:
                f.domains.append(line)
        elif line.startswith("@"):
            key, _, val = line[1:].partition(" ")
            val = val.strip()
            k = key.lower()
            if k == "name":
                f.name = val
            elif k == "description":
                f.description = val
            elif k == "source":
                f.source = val
            else:
                r.warnings.append(issue(f"unknown directive @{key} (ignored)"))
        elif _has_prefix(line, "asn:"):
            v = _strip_hash(line[4:]).strip()
            try:
                a = parse_asn(v)
            except RuleError:
                r.errors.append(issue(f"invalid ASN {v!r}"))
                continue
            if a not in f.asns:
                f.asns.append(a)
        elif _has_prefix(line, "cidr:") or _has_prefix(line, "ip:"):
            v = _strip_hash(line.partition(":")[2]).strip()
            if not _valid_cidr(v):
                r.errors.append(issue(f"invalid CIDR/IP {v!r}"))
                continue
            f.cidrs.append(v)
        elif (
            convert
            and line.startswith("!")
            and not line[1:].strip().startswith("/")
            and re.search(r"[ \t]", line[1:].strip())
            and not _is_rule(line)
        ):
            r.converted += 1  # AdBlock comment ("! Title: ...")
        else:
            if convert:
                conv_lines = convert_line(line)
                if conv_lines is not None:
                    r.converted += 1
                    for d in conv_lines:
                        try:
                            parse(d)
                        except RuleError as e:
                            r.errors.append(issue(str(e)))
                            continue
                        f.domains.append(d)
                    continue
            try:
                parse(line)
            except RuleError as e:
                if convert and line.startswith("!"):
                    r.converted += 1  # AdBlock comment ("! Title: ...")
                    continue
                r.errors.append(issue(str(e)))
                continue
            f.domains.append(normalize(line))
    f.domains = _dedup(f.domains, keep_comments=True)
    f.cidrs = _dedup(f.cidrs)
    return r


def convert_line(line: str) -> list[str] | None:
    """Translate one line from a foreign list format (None: not one)."""
    lo = line.lower()
    m = _ABP_RE.match(lo)
    if m:
        return [m.group(1)]
    if _HOSTS_RE.match(lo):
        out = []
        for h in lo.split()[1:]:
            if h.startswith("#"):
                break
            # Skip loopback aliases and addresses ("0.0.0.0 0.0.0.0").
            if h not in _HOSTS_SKIP and canonical_ip(h) is None:
                out.append("=" + h)
        return out
    m = _DNSMASQ_RE.match(lo)
    if m:
        return [d for d in (x.strip() for x in m.group(2).split("/")) if d and d != "#"]
    return None


def _one_line(s: str) -> str:
    return " ".join(s.split())


def format_file(f: RuleFile) -> str:
    """Render a file in canonical form."""
    out = [HEADER]
    if f.name:
        out.append("@name " + _one_line(f.name))
    if f.description:
        out.append("@description " + _one_line(f.description))
    if f.source:
        out.append("@source " + _one_line(f.source))
    if f.domains:
        out += ["", *f.domains]
    if f.asns:
        out += ["", *(f"asn:{a}" for a in sorted(f.asns))]
    if f.cidrs:
        out += ["", *(f"cidr:{c}" for c in f.cidrs)]
    return "\n".join(out) + "\n"


def _dedup(items: list[str], keep_comments: bool = False) -> list[str]:
    seen: set[str] = set()
    out = []
    for s in items:
        if (keep_comments and s.startswith("#")) or s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _is_rule(line: str) -> bool:
    """Whether ``line`` parses as a rule (``!rule # note`` is an exclusion,
    not an AdBlock comment)."""
    try:
        parse(line)
    except RuleError:
        return False
    return True
