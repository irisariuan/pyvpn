"""snake's domain rule format: one rule. Port of snake ``internal/match/match.go``.

One rule per line (or list entry). Blank lines and text after `` #`` are
ignored::

    example.com          domain and all its subdomains
    .example.com         subdomains only, not example.com itself
    =example.com         exactly example.com
    *.example.com        glob: * matches within one label
    **.example.com       glob: ** matches across labels
    api-?.example.com    glob: ? matches one character (not a dot)
    ~nflx                keyword: name contains "nflx"
    /^ipv4-c\\d+\\.x\\.net$/  regular expression (RE2 syntax, case-insensitive)
    re:^ipv4-c\\d+\\.x$     same, alternative syntax
    !ads.example.com     exclusion: removes matches of the rules
    drop:ads.example.com drop: block what the rule matches; beats include
                         rules, but ! still exempts a name
    drop:asn:1234        drop: block an autonomous system's prefixes
    drop:cidr:1.2.3.0/24 drop: block an address range or single IP (drop:ip: too)
    session:example.com  session: route only for whoever looked it up
    if:C;then:route:E    conditional rules (then:/else:/finally:), see route.py

Names are compared lowercase without the trailing dot.
"""

from __future__ import annotations

# mypy resolves this stdlib-private module differently per host: Linux says
# import-not-found, macOS says import-untyped and calls the other code unused.
import re
import re._parser as sre_parse  # type: ignore[import-not-found, import-untyped, unused-ignore]
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Protocol

from pyvpn.match.opts import (
    OptionError,
    Opts,
    canonical_cidr,
    canonical_ip,
    cmd_prefix,
    parse_opts,
    split_cmd,
)

DROP_PREFIX = "drop:"
SESSION_PREFIX = "session:"
ROUTE_PREFIX = "route:"
IF_PREFIX = "if:"


class Kind(StrEnum):
    SUFFIX = "suffix"  # example.com
    SUBDOMAINS = "subdomains"  # .example.com
    EXACT = "exact"  # =example.com
    GLOB = "glob"  # *.example.com
    KEYWORD = "keyword"  # ~word
    REGEX = "regex"  # /re/ or re:re
    ASN = "asn"  # drop:asn:1234 (addresses, not names)
    CIDR = "cidr"  # drop:cidr:1.2.3.0/24


class RuleError(ValueError):
    """A rule that does not parse."""


@dataclass(frozen=True)
class Pattern:
    """One parsed rule."""

    raw: str
    kind: Kind | None = None
    negate: bool = False
    drop: bool = False
    session: bool = False
    opts: Opts = field(default_factory=Opts)  # session[...] / drop[...] options
    value: str = ""
    # A literal domain suffix every match must end with ("" if none can be
    # derived): steers DNS through the target and is used for pre-resolving.
    base: str = ""
    regex: Regex | None = field(default=None, compare=False, repr=False)

    def match(self, name: str) -> bool:
        """Whether ``name`` (lowercase, no trailing dot) matches, ignoring ``negate``."""
        k = self.kind
        if k is Kind.SUFFIX:
            return name == self.value or name.endswith("." + self.value)
        if k is Kind.SUBDOMAINS:
            return name.endswith("." + self.value)
        if k is Kind.EXACT:
            return name == self.value
        if k is Kind.KEYWORD:
            return self.value in name
        if k in (Kind.GLOB, Kind.REGEX):
            return self.regex is not None and self.regex.search(name) is not None
        return False  # ASN, CIDR: addresses, not names

    def native(self) -> bool:
        """Whether a plain suffix lookup implements the rule exactly."""
        return self.kind is Kind.SUFFIX and not self.negate

    def needs_re2(self) -> bool:
        """Whether matching needs RE2 to run in bounded time: regexes, and
        wildcards that Python's backtracking ``re`` could match slowly."""
        if self.kind is Kind.REGEX:
            return True
        return self.kind is Kind.GLOB and not glob_bounded(self.value)


_LABEL_RE = re.compile(r"[a-z0-9_]([a-z0-9_\-]{0,61}[a-z0-9_])?")


def valid_domain(d: str) -> bool:
    if not d or len(d) > 253 or d.startswith(".") or d.endswith("."):
        return False
    return all(_LABEL_RE.fullmatch(label) for label in d.split("."))


def strip_comment(s: str) -> str:
    """Remove a trailing `` # comment`` and surrounding space.

    Regexes may contain `` #``: after ``/regex/`` only a `` #`` that follows
    the closing ``/`` starts a comment; ``re:regex`` runs to the end of the
    line.
    """
    s = s.strip()
    if s.startswith("#"):
        return ""
    body = s.removeprefix("!").lstrip()
    if body.startswith("re:"):
        return s
    # A /regex/ may start after a prefix too (drop:/.../, session:/.../, or
    # inside an if: expression), so track regex boundaries through the line.
    in_re = in_class = False
    prev = ""
    i = 0
    while i < len(s):
        c = s[i]
        if in_re:
            if c == "\\":
                i += 2
                continue
            if in_class:
                in_class = c != "]"
            elif c == "[":
                in_class = True
            elif c == "/":
                in_re = False
        elif c == "#" and i > 0 and s[i - 1] in " \t":
            return s[:i].strip()
        elif c == "/" and (prev == "" or prev in "!(,:;"):
            in_re = True
        if c not in " \t":
            prev = c
        i += 1
    return s


def is_route(s: str) -> bool:
    """Whether a rule (or its first line) is a conditional (if:) or route: rule."""
    t = s.strip()
    if len(t) > 3 and t[:3].lower() == IF_PREFIX:
        return True
    return len(t) > 5 and t[:5].lower() == "route" and t[5] in ":["


def _try_opts(text: str) -> Opts | None:
    try:
        return parse_opts(text)
    except OptionError:
        return None


def normalize(s: str) -> str:
    """Canonical text of a rule (lowercase, scheme/path stripped for plain
    domains). Regexes are left as written."""
    if is_route(s):
        from pyvpn.match.route import normalize_route

        return normalize_route(s)
    s = strip_comment(s)
    if not s:
        return ""
    neg = ""
    if s.startswith("!"):
        neg, s = "!", s[1:].strip()
    opts, has, rest, ok = split_cmd(s, "drop")
    if ok and has:
        # drop[options]: a drop session (domain rules only).
        o = _try_opts(opts)
        if o is not None:
            return neg + cmd_prefix("drop", o) + normalize(rest.strip())
        return neg + "drop[" + opts + "]:" + normalize(rest.strip())
    if s[: len(DROP_PREFIX)].lower() == DROP_PREFIX:
        inner = s[len(DROP_PREFIX) :].strip()
        lo = inner.lower()
        for k in ("asn:", "cidr:", "ip:"):
            if lo.startswith(k):
                v = inner[len(k) :].strip().lower()
                if k == "asn:":
                    v = v.removeprefix("as")
                return neg + DROP_PREFIX + k + v
        return neg + DROP_PREFIX + normalize(inner)
    opts, has, rest, ok = split_cmd(s, "session")
    if ok:
        o = _try_opts(opts)
        if o is None:
            # Kept as written so parse() reports the bad option.
            return neg + "session[" + opts + "]:" + normalize(rest.strip())
        return neg + cmd_prefix("session", o) + normalize(rest.strip())
    if s.startswith("/") or s.startswith("re:"):
        return neg + s
    s = s.lower()
    if s.startswith("~"):
        return neg + s
    prefix = ""
    if s.startswith("="):
        prefix, s = "=", s[1:]
    url = s.startswith(("https://", "http://"))
    s = s.removeprefix("https://").removeprefix("http://")
    # In a URL, ? and # start the query and fragment; elsewhere ? is a wildcard.
    m = re.search(r"[/:?#]" if url else r"[/:]", s)
    if m:
        s = s[: m.start()]
    s = s.removesuffix(".")
    return neg + prefix + s


def parse(raw: str) -> Pattern:
    """Parse one rule (raises RuleError)."""
    s = normalize(raw)
    if not s:
        raise RuleError("empty rule")
    negate = False
    if s.startswith("!"):
        negate, s = True, s[1:]
    if s.startswith(DROP_PREFIX) or s.startswith("drop["):
        if negate:
            raise RuleError(
                "! and drop: cannot be combined; write !name to exempt a name from drop rules"
            )
        return _parse_drop(s)
    if split_cmd(s, "session")[3]:
        if negate:
            raise RuleError("! and session: cannot be combined; write !name to exempt a name")
        return _parse_session(s)
    if is_route(s):
        raise RuleError("if: and route: rules are compiled with the rule list (if:...;then:...)")
    raw_s = ("!" if negate else "") + s
    if s.startswith("re:") or s.startswith("/"):
        expr = s.removeprefix("re:")
        if s.startswith("/"):
            if len(s) < 3 or not s.endswith("/"):
                raise RuleError("regex must be written /.../")
            expr = s[1:-1]
        rx = compile_regex(expr)
        p = Pattern(raw_s, Kind.REGEX, negate, value=expr, base=regex_base(expr), regex=rx)
    elif s.startswith("~"):
        kw = s[1:]
        if not kw or " " in kw or "\t" in kw:
            raise RuleError("keyword must be non-empty and contain no spaces")
        p = Pattern(raw_s, Kind.KEYWORD, negate, value=kw)
    elif s.startswith("="):
        d = s[1:]
        if not valid_domain(d):
            raise RuleError(f"invalid domain {d!r}")
        p = Pattern(raw_s, Kind.EXACT, negate, value=d, base=d)
    elif "*" in s or "?" in s:
        if "***" in s:
            raise RuleError("use * (one label) or ** (any labels)")
        try:
            rx = _compile(glob_to_regex(s), ignore_case=False)
        except (re.error, _Re2Error) as e:
            raise RuleError(f"bad wildcard: {e}") from None
        p = Pattern(raw_s, Kind.GLOB, negate, value=s, base=glob_base(s), regex=rx)
    elif s.startswith("."):
        d = s[1:]
        if not valid_domain(d):
            raise RuleError(f"invalid domain {d!r}")
        if "." not in d:
            raise RuleError(
                f"{s!r} would match a whole top-level domain; use **.{d} if you really mean it"
            )
        p = Pattern(raw_s, Kind.SUBDOMAINS, negate, value=d, base=d)
    else:
        if not valid_domain(s):
            raise RuleError(f"invalid domain {s!r}")
        if "." not in s:
            raise RuleError(
                f"{s!r} would match a whole top-level domain; use **.{s} if you really mean it"
            )
        p = Pattern(raw_s, Kind.SUFFIX, negate, value=s, base=s)
    if p.base and "." not in p.base:
        p = replace(p, base="")  # a bare TLD is too broad to steer DNS for
    return p


def parse_asn(v: str) -> int:
    """``1234`` or ``AS1234`` (raises RuleError)."""
    t = v.strip()
    if t[:2].lower() == "as":
        t = t[2:]
    if not re.fullmatch(r"[0-9]+", t) or not 0 < int(t) < 1 << 32:
        raise RuleError(f"invalid ASN {v!r}")
    return int(t)


def parse_cidr(v: str) -> str:
    """A network (host bits cleared) or a single IP, canonical (raises RuleError)."""
    t = v.strip()
    c = canonical_cidr(t) or canonical_ip(t)
    if c is None:
        raise RuleError(f"invalid CIDR/IP {t!r}")
    return c


def _parse_drop(s: str) -> Pattern:
    """``drop:<rule>``, ``drop:asn:N``, ``drop:cidr:X`` or ``drop[opts]:<domain rule>``."""
    opts, has, rest, ok = split_cmd(s, "drop")
    if ok and has:
        try:
            o = parse_opts(opts)
        except OptionError as e:
            raise RuleError(f"drop[...]: {e}") from None
        lo = rest.lower()
        if lo.startswith(("asn:", "cidr:", "ip:")):
            raise RuleError(
                "drop[...] options need a domain rule (a drop session starts with a DNS "
                "lookup); drop:asn:/cidr: block for every device"
            )
        q = _parse_drop(DROP_PREFIX + rest)
        return replace(q, raw=s, opts=o)
    inner = s[len(DROP_PREFIX) :]
    if inner.startswith("asn:"):
        try:
            n = parse_asn(inner[4:])
        except RuleError:
            raise RuleError(f"invalid ASN {inner[4:]!r}") from None
        return Pattern(s, Kind.ASN, drop=True, value=str(n))
    if inner.startswith(("cidr:", "ip:")):
        return Pattern(s, Kind.CIDR, drop=True, value=parse_cidr(inner.partition(":")[2]))
    if not inner:
        raise RuleError("drop: needs a rule, e.g. drop:ads.example.com")
    q = parse(inner)
    if q.negate or q.drop or q.session:
        raise RuleError("drop: must be followed by a domain rule, asn: or cidr:")
    return replace(q, raw=s, drop=True)


def _parse_session(s: str) -> Pattern:
    """``session:<domain rule>`` or ``session[opts]:<rule>``."""
    opts, _, inner, _ = split_cmd(s, "session")
    try:
        o = parse_opts(opts)
    except OptionError as e:
        raise RuleError(f"session[...]: {e}") from None
    if not inner:
        raise RuleError("session: needs a domain rule, e.g. session:example.com")
    q = parse(inner)
    if q.negate or q.drop or q.session or q.kind in (Kind.ASN, Kind.CIDR):
        raise RuleError(
            "session: must be followed by a domain rule (a session starts with a DNS lookup)"
        )
    if o.permanent():
        raise RuleError("session[...]: a negative ttl and set= are for route and drop actions")
    return replace(q, raw=s, session=True, opts=o)


def glob_to_regex(g: str) -> str:
    out = ["^"]
    i = 0
    while i < len(g):
        c = g[i]
        if c == "*":
            if i + 1 < len(g) and g[i + 1] == "*":
                out.append(".+")
                i += 1
            else:
                out.append("[^.]*")
        elif c == "?":
            out.append("[^.]")
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return "".join(out)


def glob_bounded(g: str) -> bool:
    """Whether Python's ``re`` matches the wildcard in bounded time.

    At most one ``**`` (``.+``) and at most one ``*``/``**`` per label: each
    ``[^.]*`` then stops at its label's dot, so only the one ``.+`` can
    backtrack across the name (quadratic at worst in a 253-byte name). More
    unbounded stars nest their backtracking and need RE2.
    """
    if g.count("**") > 1:
        return False
    return all(len(re.findall(r"\*+", label)) <= 1 for label in g.split("."))


def glob_base(g: str) -> str:
    """The labels after the last label containing a wildcard."""
    labels = g.split(".")
    last = -1
    for i, label in enumerate(labels):
        if "*" in label or "?" in label:
            last = i
    base = ".".join(labels[last + 1 :])
    return base if valid_domain(base) else ""


# --- regular expressions (RE2 subset of Python's re) ---------------------
#
# Rule regexes and wildcards run on the DNS path and may come from imported
# lists, so they are matched with RE2 (linear time) when the optional
# ``google-re2`` package is installed (``pip install snakevpn[re2]``). Without
# it, Python's backtracking ``re`` compiles them, but ``build_matcher``
# refuses to activate rules whose ``Pattern.needs_re2()`` (a regex can take
# exponential time in ``re``); ``pyvpn rules check`` only warns. Syntax is the
# same either way: the checks below reject what RE2 lacks or reads
# differently before either engine compiles.


class Regex(Protocol):
    def search(self, string: str, /) -> object | None: ...


try:
    import re2 as _re2

    _Re2Error: type[Exception] = _re2.error
except ImportError:  # optional dependency
    _re2 = None
    _Re2Error = re.error

ENGINE = "re" if _re2 is None else "re2"
"""The regex engine at import: "re2" (linear time) or "re" (backtracking)."""


def regex_engine() -> str:
    """The regex engine in use: "re2" (linear time) or "re" (backtracking)."""
    return "re" if _re2 is None else "re2"


def _compile(expr: str, *, ignore_case: bool) -> Regex:
    if _re2 is not None:
        options = _re2.Options()
        options.case_sensitive = not ignore_case
        options.log_errors = False
        rx: Regex = _re2.compile(expr, options)
        return rx
    return re.compile(expr, (re.IGNORECASE if ignore_case else 0) | re.ASCII)


_UNSUPPORTED = {
    sre_parse.ASSERT: "lookaround",
    sre_parse.ASSERT_NOT: "lookaround",
    sre_parse.GROUPREF: "backreferences",
    sre_parse.GROUPREF_EXISTS: "conditional groups",
    sre_parse.ATOMIC_GROUP: "atomic groups",
    sre_parse.POSSESSIVE_REPEAT: "possessive quantifiers",
}


def _walk_unsupported(items: Any) -> str | None:
    for op, av in items:
        if op in _UNSUPPORTED:
            return str(_UNSUPPORTED[op])
        for sub in _children(op, av):
            found = _walk_unsupported(sub)
            if found:
                return found
    return None


def _children(op: Any, av: Any) -> list[Any]:
    if op is sre_parse.SUBPATTERN:
        return [av[-1]]
    if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT, sre_parse.POSSESSIVE_REPEAT):
        return [av[2]]
    if op is sre_parse.BRANCH:
        return list(av[1])
    if op is sre_parse.ATOMIC_GROUP:
        return [av]
    return []


_RE2_ESCAPES = {
    "Z": r"\Z (use $)",
    "N": r"\N{...}",
    "u": r"\u",
    "U": r"\U",
}
_RE2_FLAGS = set("ims-")  # inline flags both engines read the same way
_REPEAT_RE = re.compile(r"\{(\d*)(,?)(\d*)\}")
_RE2_REPEAT_RE = re.compile(r"\{(0|[1-9]\d*)(,(0|[1-9]\d*)?)?\}")
_RE2_MAX_REPEAT = 1000


def _scan_unsupported(expr: str) -> str | None:
    """Constructs Python's ``re`` parses that RE2 rejects or reads differently
    (the parse tree no longer shows them)."""
    i, n = 0, len(expr)
    in_class = False
    class_start = 0
    while i < n:
        c = expr[i]
        if c == "\\":
            nxt = expr[i + 1 : i + 2]
            if nxt in _RE2_ESCAPES:
                return _RE2_ESCAPES[nxt]
            i += 2
            continue
        if in_class:
            if c == "]" and i >= class_start:
                in_class = False
            elif c == "[":
                return "[ inside a character class"
            i += 1
            continue
        if c == "[":
            in_class = True
            class_start = i + 1
            if expr[class_start : class_start + 1] == "^":
                class_start += 1
            if expr[class_start : class_start + 1] == "]":
                class_start += 1  # a leading ] is a literal
            i += 1
            continue
        if c == "(" and expr[i + 1 : i + 2] == "?":
            rest = expr[i + 2 :]
            if rest.startswith("#"):
                return "a (?#...) comment"
            m = re.match(r"[A-Za-z-]+", rest)
            if m and not rest.startswith("P"):
                bad = set(m.group()) - _RE2_FLAGS
                if bad:
                    return f"inline flag {''.join(sorted(bad))!r}"
        if c == "{":
            m = _REPEAT_RE.match(expr, i)
            if m and m.group() != "{}":
                r = _RE2_REPEAT_RE.fullmatch(m.group())
                if not r:
                    return f"repetition {m.group()}"
                if any(int(g) > _RE2_MAX_REPEAT for g in (r.group(1), r.group(3)) if g):
                    return f"repetition {m.group()} (more than {_RE2_MAX_REPEAT})"
                i = m.end()
                continue
        i += 1
    return None


def compile_regex(expr: str) -> Regex:
    """Compile a rule regex: RE2 syntax, case-insensitive (raises RuleError)."""
    bad = _scan_unsupported(expr)
    if bad:
        raise RuleError(f"bad regex: {bad} is not supported (RE2 syntax)")
    try:
        tree = sre_parse.parse(expr)
        re.compile(expr, re.IGNORECASE | re.ASCII)
    except (re.error, OverflowError, RecursionError) as e:
        raise RuleError(f"bad regex: {e}") from None
    bad = _walk_unsupported(tree)
    if bad:
        raise RuleError(f"bad regex: {bad} is not supported (RE2 syntax)")
    try:
        return _compile(expr, ignore_case=True)
    except (re.error, _Re2Error) as e:
        raise RuleError(f"bad regex: {e}") from None


def regex_base(expr: str) -> str:
    """A literal domain suffix a regex ends with, e.g.
    ``^ipv4-.*\\.oca\\.nflxvideo\\.net$`` -> ``oca.nflxvideo.net``."""
    try:
        items = list(sre_parse.parse(expr))
    except (re.error, OverflowError, RecursionError):
        return ""
    if len(items) < 2:
        return ""
    end_op, end_av = items[-1]
    if end_op is not sre_parse.AT or end_av not in (sre_parse.AT_END, sre_parse.AT_END_STRING):
        return ""  # unanchored: anything may follow
    chars: list[str] = []
    for op, av in reversed(items[:-1]):
        if op is not sre_parse.LITERAL:
            break
        chars.append(chr(av))
    if not chars:
        return ""
    s = "".join(reversed(chars)).lower()
    i = s.find(".")
    if i < 0:
        return ""
    s = s[i + 1 :]
    return s if valid_domain(s) else ""
