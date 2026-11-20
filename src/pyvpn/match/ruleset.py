"""A compiled rule list. Port of snake ``internal/match`` ``Set``.

``RuleSet.match_any`` tests the query name and then its CNAME chain: with
CNAME following a rule also matches when any name in the answer's chain
matches, so ``**.akamaized.net`` catches services that CNAME into Akamai.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from pyvpn.match.opts import Opts
from pyvpn.match.pattern import Kind, Pattern, RuleError, is_route, parse, strip_comment
from pyvpn.match.route import ACT_ROUTE, CondHit, Expr, Route, group, parse_route


@dataclass(frozen=True)
class LineError:
    """A parse error for one rule (``index`` is 0-based)."""

    index: int
    rule: str
    error: str


@dataclass(frozen=True)
class Step:
    """A rule that starts route or drop sessions: if:/route: or drop[...]:."""

    line: int
    route: Route | None = None
    drop: Pattern | None = None

    @property
    def raw(self) -> str:
        if self.route is not None:
            return self.route.raw
        assert self.drop is not None
        return self.drop.raw

    def match(self, name: str) -> bool:
        if self.route is not None:
            return self.route.match_name(name)
        return self.drop is not None and self.drop.match(name)


@dataclass(frozen=True)
class Result:
    """Explains a match decision."""

    matched: bool = False
    name: str = ""  # the name in the chain that matched
    rule: str = ""  # the include (or drop) rule that matched
    drop: bool = False  # a drop: rule matched: block, do not route
    session: bool = False  # a session: rule matched
    route: bool = False  # route/drop session rules matched (steps_for lists them)
    opts: Opts = field(default_factory=Opts)  # options of the session: rule
    cond: tuple[CondHit, ...] = ()  # if: atoms the names matched
    excluded: str = ""  # the exclusion that vetoed it


class _Index:
    """Earliest matching pattern without scanning plain domain rules:
    suffix/subdomain/exact rules are looked up by the name and each parent
    domain; only globs, keywords and regexes are scanned."""

    def __init__(self, pats: Sequence[Pattern]) -> None:
        self.whole: dict[str, int] = {}  # name == value: suffix, exact
        self.sub: dict[str, int] = {}  # name ends in "." + value: suffix, subdomains
        self.slow: list[int] = []
        self.pats = pats
        for i, p in enumerate(pats):
            if p.kind is Kind.SUFFIX:
                self.whole.setdefault(p.value, i)
                self.sub.setdefault(p.value, i)
            elif p.kind is Kind.EXACT:
                self.whole.setdefault(p.value, i)
            elif p.kind is Kind.SUBDOMAINS:
                self.sub.setdefault(p.value, i)
            else:
                self.slow.append(i)

    def first(self, name: str) -> int:
        """Index of the earliest pattern matching ``name``, or -1."""
        best = self.whole.get(name, -1)
        rest = name
        while True:
            dot = rest.find(".")
            if dot < 0:
                break
            rest = rest[dot + 1 :]
            i = self.sub.get(rest, -1)
            if i >= 0 and (best < 0 or i < best):
                best = i
        for i in self.slow:
            if best >= 0 and i > best:
                break
            if self.pats[i].match(name):
                if best < 0 or i < best:
                    best = i
                break
        return best


class RuleSet:
    """A compiled rule list. Do not modify the lists after the first match."""

    def __init__(self) -> None:
        self.include: list[Pattern] = []
        self.exclude: list[Pattern] = []
        self.drop: list[Pattern] = []  # drop: domain rules
        self.session: list[Pattern] = []  # session: domain rules
        self.routes: list[Route] = []  # if:...;then:... and route: rules
        # Rules that start route or drop sessions, in the order written.
        self.steps: list[Step] = []
        self.drop_asns: list[int] = []  # drop:asn:
        self.drop_cidrs: list[str] = []  # drop:cidr:
        self._built = False

    # --- compiling --------------------------------------------------------

    @classmethod
    def compile(cls, rules: Sequence[str]) -> tuple[RuleSet, list[LineError]]:
        """Parse rules, skipping blanks/comments and reporting bad lines.
        A route: rule may span several entries (see ``route.group``)."""
        s = cls()
        errs: list[LineError] = []
        for lg in group(rules):
            i, r = lg.first, lg.text
            if is_route(r):
                try:
                    rt = parse_route(r)
                except RuleError as e:
                    errs.append(LineError(i, r, str(e)))
                    continue
                s.routes.append(rt)
                s.steps.append(Step(i, route=rt))
                continue
            if not strip_comment(r):
                continue
            try:
                p = parse(r)
            except RuleError as e:
                errs.append(LineError(i, r, str(e)))
                continue
            if p.negate:
                s.exclude.append(p)
            elif p.kind is Kind.ASN:
                s.drop_asns.append(int(p.value))
            elif p.kind is Kind.CIDR:
                s.drop_cidrs.append(p.value)
            elif p.drop:
                s.drop.append(p)
                if not p.opts.is_zero():
                    s.steps.append(Step(i, drop=p))
            elif p.session:
                s.session.append(p)
            else:
                s.include.append(p)
        return s, errs

    @classmethod
    def must_compile(cls, rules: Sequence[str]) -> RuleSet:
        """Compile rules already validated, dropping bad ones."""
        return cls.compile(rules)[0]

    def _build(self) -> None:
        if self._built:
            return
        self._plain_drop = [p for p in self.drop if p.opts.is_zero()]
        self._inc = _Index(self.include)
        self._exc = _Index(self.exclude)
        self._drp = _Index(self._plain_drop)
        self._ses = _Index(self.session)
        self._built = True

    # --- matching ---------------------------------------------------------

    def steps_for(self, *names: str) -> list[Step]:
        """The steps any of the names matches, top to bottom."""
        return [st for st in self.steps if any(n and st.match(n) for n in names)]

    def _first_step(self, names: Sequence[str], drop_only: bool) -> tuple[Step, str] | None:
        for st in self.steps:
            if drop_only and st.drop is None:
                continue
            for n in names:
                if st.match(n):
                    return st, n
        return None

    def match_any(self, *names: str) -> Result:
        """Test every name (query name first, then the CNAME chain).

        A name matching an exclusion vetoes the whole answer; otherwise a name
        matching a drop rule blocks it, then session rules, then include rules
        are considered. Among the rules matching the first matching name, the
        earliest is reported.
        """
        self._build()
        for n in names:
            i = self._exc.first(n)
            if i >= 0:
                return Result(excluded=self.exclude[i].raw, name=n)
        for n in names:
            i = self._drp.first(n)
            if i >= 0:
                return Result(matched=True, drop=True, name=n, rule=self._plain_drop[i].raw)
        # drop[...] rules: they and every other route/drop rule matching apply.
        hit = self._first_step(names, True)
        if hit:
            return Result(matched=True, route=True, name=hit[1], rule=hit[0].raw)
        for n in names:
            i = self._ses.first(n)
            if i >= 0:
                p = self.session[i]
                return Result(matched=True, session=True, name=n, rule=p.raw, opts=p.opts)
        # if: atoms: always routed; the addresses count for their conditions.
        hits: list[CondHit] = []
        first = first_rule = ""
        for r in self.routes:
            if r.if_ is None:
                continue
            for a in r.if_.positive():
                for n in names:
                    if a.atom is not None and a.atom.match(n):
                        hits.append(CondHit(r.raw, a.id))
                        if not first:
                            first, first_rule = n, r.raw
                        break
        if hits:
            return Result(matched=True, name=first, rule=first_rule, cond=tuple(hits))
        hit = self._first_step(names, False)
        if hit:
            return Result(matched=True, route=True, name=hit[1], rule=hit[0].raw)
        for n in names:
            i = self._inc.first(n)
            if i >= 0:
                return Result(matched=True, name=n, rule=self.include[i].raw)
        return Result()

    # --- properties of the set -------------------------------------------

    def empty(self) -> bool:
        """No include rules (session: and route: rules count)."""
        return not (self.include or self.session or self.routes)

    def has_sessions(self) -> bool:
        return bool(self.session or self.routes)

    def has_conds(self) -> bool:
        return any(r.if_ is not None for r in self.routes)

    def cond_hits(self, *names: str) -> list[CondHit]:
        """The if: atoms (negated ones too) any of the names matches."""
        hits: list[CondHit] = []
        for r in self.routes:
            if r.if_ is None:
                continue
            for a in r.if_.all():
                if any(a.atom is not None and a.atom.match(n) for n in names):
                    hits.append(CondHit(r.raw, a.id))
        return hits

    def route(self, raw: str) -> Route | None:
        return next((r for r in self.routes if r.raw == raw), None)

    def has_drops(self) -> bool:
        return bool(self.drop or self.drop_asns or self.drop_cidrs)

    def has_drop_sessions(self) -> bool:
        return any(r.has_drop() for r in self.routes) or any(
            not p.opts.is_zero() for p in self.drop
        )

    def drop_suffixes(self, degraded: bool) -> list[str] | None:
        """Plain drop: suffix rules a suffix-only resolver can apply itself.
        None with exclusions unless ``degraded``: it cannot honour them."""
        if self.exclude and not degraded:
            return None
        return [p.value for p in self.drop if p.kind is Kind.SUFFIX and p.opts.is_zero()]

    def native_suffixes(self) -> list[str] | None:
        """Include rules a suffix-only resolver can handle; None with exclusions."""
        if self.exclude:
            return None
        return self.plain_suffixes()

    def plain_suffixes(self) -> list[str]:
        """Include rules a suffix-only resolver can match, ignoring exclusions."""
        return [p.value for p in self.include if p.native()]

    def needs_inspector(self) -> bool:
        """Whether some rules need DNS answer inspection."""
        if self.session or self.routes:
            return True
        if self.exclude:
            return bool(self.include or self.drop)
        if any(not p.native() for p in self.include):
            return True
        return any(p.kind is not Kind.SUFFIX or not p.opts.is_zero() for p in self.drop)

    def bases(self) -> list[str]:
        """Literal domain suffixes covering the include rules (to send their
        DNS through the target and for pre-resolving). Keywords and
        unanchored regexes contribute nothing."""
        pats: list[Pattern] = [*self.include, *self.session]
        for r in self.routes:
            xs: list[Expr | None] = [r.if_]
            xs.extend(a.expr for a in r.branches() if a.kind == ACT_ROUTE)
            for x in xs:
                if x is not None:
                    pats.extend(a.atom for a in x.positive() if a.atom is not None)
        return _unique(p.base for p in pats if p.base)


def _unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))
