"""Conditional rules. Port of snake ``internal/match/route.go``::

    if:COND;then:ACTION;else:ACTION;finally:ACTION

``else:`` and ``finally:`` are optional. ACTION is ``route[options]:EXPR`` or
``drop[options]:EXPR``; options as for ``session[...]:``.

The ``if:`` part's names are routed like plain rules; the addresses they
resolve to are remembered per atom. When a name of a branch is looked up, the
condition holds while there is a live connection to an address of the
condition's atoms (``not:`` negates). If it holds, ``then:`` names get
``then:``'s action, otherwise ``else:`` names get ``else:``'s; ``finally:``
names get ``finally:``'s action either way, unless the branch taken also has
the name.

A plain ``route[options]:EXPR`` (no ``if:``) always starts sessions. The old
form ``route[options]:EXPR;if:COND`` is read as ``if:COND;then:route[...]:EXPR``.

EXPR and COND are a domain rule, or ``not:EXPR``, ``and:(EXPR, ...)``,
``or:(EXPR, ...)``, or ``(EXPR)`` / ``(EXPR, EXPR, ...)`` for ``and:``. A rule
may span lines: it continues after a line ending in ``;``, before a line
starting with ``;`` or ``then:``/``else:``/``finally:``, and while
parentheses are open.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from pyvpn.match.opts import OptionError, Opts, cmd_prefix, parse_opts, split_cmd
from pyvpn.match.pattern import (
    IF_PREFIX,
    Pattern,
    RuleError,
    is_route,
    parse,
    strip_comment,
)

ACT_ROUTE = "route"
ACT_DROP = "drop"


@dataclass(eq=False)
class Expr:
    """A parsed condition or name expression."""

    op: str  # atom, not, and, or
    atom: Pattern | None = None
    id: int = 0  # atom number within its expression (1-based)
    kids: list[Expr] = field(default_factory=list)

    def match_name(self, name: str) -> bool:
        return self.eval(lambda a: a.atom is not None and a.atom.match(name))

    def eval(self, f: Callable[[Expr], bool]) -> bool:
        """Evaluate with atom truth values from ``f``."""
        if self.op == "atom":
            return f(self)
        if self.op == "not":
            return not self.kids[0].eval(f)
        if self.op == "and":
            return all(k.eval(f) for k in self.kids)
        if self.op == "or":
            return any(k.eval(f) for k in self.kids)
        return False

    def positive(self) -> list[Expr]:
        """The atoms not under an odd number of ``not:``."""
        out: list[Expr] = []

        def walk(e: Expr, neg: bool) -> None:
            if e.op == "atom":
                if not neg:
                    out.append(e)
            elif e.op == "not":
                walk(e.kids[0], not neg)
            else:
                for k in e.kids:
                    walk(k, neg)

        walk(self, False)
        return out

    def all(self) -> list[Expr]:
        out: list[Expr] = []

        def walk(e: Expr) -> None:
            if e.op == "atom":
                out.append(e)
            for k in e.kids:
                walk(k)

        walk(self)
        return out


@dataclass(eq=False)
class Action:
    """One branch of a conditional rule."""

    kind: str  # route or drop
    opts: Opts
    expr: Expr

    def match(self, name: str) -> bool:
        return self.expr.match_name(name)


@dataclass(eq=False)
class Route:
    """A conditional rule (or a plain route: rule: no ``if_``, the action in ``then``)."""

    raw: str
    then: Action
    if_: Expr | None = None  # None: always
    else_: Action | None = None
    finally_: Action | None = None

    def branches(self) -> list[Action]:
        return [a for a in (self.then, self.else_, self.finally_) if a is not None]

    def match_name(self, name: str) -> bool:
        return any(a.match(name) for a in self.branches())

    def pick(self, cond: bool, *names: str) -> Action | None:
        """The action for a name when the condition is (not) met: then: (or
        else:) first, then finally:. None: nothing to do."""
        branch = self.then if cond else self.else_
        for a in (branch, self.finally_):
            if a is None:
                continue
            for n in names:
                if n and a.match(n):
                    return a
        return None

    def has_drop(self) -> bool:
        return any(a.kind == ACT_DROP for a in self.branches())


@dataclass(frozen=True)
class CondHit:
    """An address belongs to atom ``atom`` of the if: part of ``rule``."""

    rule: str
    atom: int


def _try_opts(text: str) -> Opts | None:
    try:
        return parse_opts(text)
    except OptionError:
        return None


def normalize_route(s: str) -> str:
    """A route rule's text as written (atoms are normalized when parsed),
    without comments and trailing spaces; the old ``route:...;if:...`` form is
    rewritten as ``if:...;then:route:...``."""
    out: list[str] = []
    for line in s.split("\n"):
        lead = line[: len(line) - len(line.lstrip(" \t"))]
        line = strip_comment(line)
        if not line:
            continue
        if not out:
            # Canonical command prefix: route: or route[options]:
            opts, _, rest, ok = split_cmd(line, "route")
            if ok:
                o = _try_opts(opts)
                if o is not None:
                    line = cmd_prefix("route", o) + rest
            out.append(line)
            continue
        out.append(lead + line)
    text = "\n".join(out)
    conv = convert_legacy(text)
    return conv if conv is not None else text


def _starts_branch(s: str) -> bool:
    return s.lower().startswith(("then:", "else:", "finally:"))


def _join_lines(text: str) -> str:
    b = ""
    for line in text.split("\n"):
        line = strip_comment(line).strip()
        # A line starting a branch needs no ";" before it.
        if _starts_branch(line) and b and not b.endswith(";"):
            b += ";"
        b += line
    return b


def is_legacy_route(text: str) -> bool:
    """Whether ``text`` is the old ``route:EXPR;if:COND`` form."""
    return convert_legacy(text) is not None


def convert_legacy(text: str) -> str | None:
    """Rewrite ``route[options]:EXPR;if:COND`` as ``if:COND;then:route[options]:EXPR``."""
    joined = _join_lines(text)
    opts, _, rest, ok = split_cmd(joined, "route")
    if not ok:
        return None
    o = _try_opts(opts)
    if o is None:
        return None
    p = _ExprParser(rest)
    try:
        p.expr()
    except RuleError:
        return None
    expr_text = rest[: p.i].strip()
    if not p.eat(";") or not p.eat(IF_PREFIX):
        return None
    cond_text = rest[p.i :].strip()
    try:
        _ExprParser(cond_text).expr()
    except RuleError:
        return None
    sep = ";\n" if "\n" in text.strip() else ";"
    return IF_PREFIX + cond_text + sep + "then:" + cmd_prefix(ACT_ROUTE, o) + expr_text


def parse_route(text: str) -> Route:
    """Parse a conditional or route: rule, possibly spanning lines (raises RuleError)."""
    norm = normalize_route(text)
    s = _join_lines(norm)
    if s[:3].lower() == IF_PREFIX:
        p = _ExprParser(s[3:])
        try:
            cond = p.expr()
        except RuleError as e:
            raise RuleError(f"if: {e}") from None
        if not p.eat(";") or not p.eat("then:"):
            raise RuleError(
                "expected ;then:ACTION after the if: condition (if:COND;then:route:EXPR)"
            )
        r = Route(raw=norm, if_=cond, then=p.action("then"))
        for br in ("else", "finally"):
            save = p.i
            if not p.eat(";"):
                break
            if not p.eat(br + ":"):
                p.i = save
                continue
            a = p.action(br)
            if br == "else":
                r.else_ = a
            else:
                r.finally_ = a
        p.eat(";")
        if p.i < len(p.s):
            rest = p.s[p.i :]
            lo = rest.lstrip(" \t;").lower()
            if lo.startswith(("then:", "else:", "finally:", "if:")):
                raise RuleError(
                    f"unexpected {rest!r}: the parts go in the order if:, then:, else:, "
                    "finally:, each once"
                )
            raise RuleError(f"unexpected {rest!r} at the end")
        _number(cond)
        if not cond.positive():
            raise RuleError("if: needs at least one condition that is not negated")
        for a in r.branches():
            _number(a.expr)
        return r
    opts, _, rest, ok = split_cmd(s, "route")
    if not ok:
        raise RuleError("a conditional rule starts with if: (if:COND;then:route:EXPR) or route:")
    try:
        o = parse_opts(opts)
    except OptionError as e:
        raise RuleError(f"route[...]: {e}") from None
    p = _ExprParser(rest)
    try:
        x = p.expr()
    except RuleError as e:
        raise RuleError(f"route: {e}") from None
    p.eat(";")
    if p.i < len(p.s):
        raise RuleError(f"unexpected {p.s[p.i :]!r} at the end")
    _number(x)
    return Route(raw=norm, then=Action(ACT_ROUTE, o, x))


def _number(x: Expr) -> None:
    for n, a in enumerate(x.all(), start=1):
        a.id = n


_BAD_ATOM_PREFIXES = (
    "re:", "drop:", "drop[", "session:", "session[", "route:", "route[", "if:",
    "then:", "else:", "finally:", "asn:", "cidr:", "ip:", "!",
)  # fmt: skip


class _ExprParser:
    def __init__(self, s: str) -> None:
        self.s = s
        self.i = 0

    def skip(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1

    def eat(self, tok: str) -> bool:
        self.skip()
        if self.s[self.i : self.i + len(tok)].lower() == tok.lower():
            self.i += len(tok)
            return True
        return False

    def action(self, part: str) -> Action:
        """``route[options]:EXPR`` or ``drop[options]:EXPR``."""
        self.skip()
        rest = self.s[self.i :]
        for kind in (ACT_ROUTE, ACT_DROP):
            opts, _, after, ok = split_cmd(rest, kind)
            if not ok:
                continue
            try:
                o = parse_opts(opts)
            except OptionError as e:
                raise RuleError(f"{part}: {kind}[...]: {e}") from None
            self.i = len(self.s) - len(after)
            try:
                x = self.expr()
            except RuleError as e:
                raise RuleError(f"{part}: {kind}: {e}") from None
            return Action(kind, o, x)
        raise RuleError(f"{part}: needs an action: route[options]:EXPR or drop[options]:EXPR")

    def expr(self) -> Expr:
        if self.eat("not:"):
            return Expr("not", kids=[self.expr()])
        if self.eat("and:"):
            return self.list("and")
        if self.eat("or:"):
            return self.list("or")
        if self.eat("("):
            # (x) groups; (x, y, ...) is and:(x, y, ...).
            x = Expr("and")
            while True:
                x.kids.append(self.expr())
                if self.eat(","):
                    continue
                if self.eat(")"):
                    break
                raise RuleError("expected , or )")
            return x.kids[0] if len(x.kids) == 1 else x
        return self.atom()

    def list(self, op: str) -> Expr:
        if not self.eat("("):
            raise RuleError(f"{op}: needs ( ... ), e.g. {op}:(a.com, b.com)")
        x = Expr(op)
        while True:
            x.kids.append(self.expr())
            if self.eat(","):
                continue
            if self.eat(")"):
                break
            raise RuleError(f"expected , or ) in {op}:( ... )")
        return x

    def atom(self) -> Expr:
        self.skip()
        start = self.i
        s = self.s
        if self.i < len(s) and s[self.i] == "/":
            # /regex/: up to the next unescaped slash.
            self.i += 1
            while self.i < len(s) and s[self.i] != "/":
                if s[self.i] == "\\":
                    self.i += 1
                self.i += 1
            if self.i >= len(s):
                raise RuleError("unterminated /regex/")
            self.i += 1
        else:
            while self.i < len(s) and s[self.i] not in ",(); \t":
                self.i += 1
        text = s[start : self.i]
        if not text:
            if self.i < len(s):
                raise RuleError(f"expected a domain rule at {s[self.i :]!r}")
            raise RuleError("expected a domain rule")
        if text.lower().startswith(_BAD_ATOM_PREFIXES):
            raise RuleError(
                f"{text!r}: only domain rules (and not:, and:, or:) go in an expression; "
                "write regexes as /.../"
            )
        try:
            pat = parse(text)
        except RuleError as e:
            raise RuleError(f"{text!r}: {e}") from None
        return Expr("atom", atom=pat)


@dataclass(frozen=True)
class Logical:
    """One rule built from one or more lines."""

    first: int  # index of its first line
    text: str  # its lines, joined with newlines


def group(lines: Sequence[str]) -> list[Logical]:
    """Join the lines of multi-line if:/route: rules. Other lines stay as they are.

    One pass: the parenthesis depth is kept per line. Inside open parentheses
    a line continues the rule only when it reads as more of the expression
    (the previous line ends in ``(``, ``,`` or ``;``, or it starts with
    ``)``, ``,``, ``;`` or a branch), so an unclosed ``(`` makes that rule an
    error instead of swallowing the rest of the list.
    """
    out: list[Logical] = []
    n = len(lines)
    i = 0
    while i < n:
        head = strip_comment(lines[i]).strip()
        if not is_route(head):
            out.append(Logical(i, lines[i]))
            i += 1
            continue
        depth = _depth(head)
        last = head  # the last non-blank line of the rule, comment stripped
        end = j = i  # end: index of that line
        while j + 1 < n:
            nxt = strip_comment(lines[j + 1]).strip()
            if not nxt:
                # Inside parentheses skip blank lines; anywhere, skip comment
                # lines, so a comment between branches does not end the rule.
                if depth > 0 or lines[j + 1].strip():
                    j += 1
                    continue
                break
            if depth > 0:
                more = not is_route(nxt) and (
                    last.endswith(("(", ",", ";"))
                    or nxt.startswith((")", ",", ";"))
                    or _starts_branch(nxt)
                )
            elif is_route(nxt):
                # A new if:/route: rule starts here, except the if: that
                # completes the legacy ``route:EXPR;`` / ``if:COND`` form.
                more = (
                    last.endswith(";")
                    and nxt[:3].lower() == "if:"
                    and head[:5].lower() == "route"
                    and not _has_if(lines[i : end + 1])
                )
            else:
                # A plain rule after a trailing ; is its own rule, not more of
                # this one; only a branch or a leading ; continues it.
                more = nxt.startswith(";") or _starts_branch(nxt)
            if not more:
                break
            j += 1
            end = j
            depth += _depth(nxt)
            last = nxt
        out.append(Logical(i, "\n".join(lines[i : end + 1])))
        i = end + 1
    return out


def _has_if(rule_lines: Sequence[str]) -> bool:
    """Whether a legacy ``route:`` rule already has its ``;if:`` part."""
    return any(";if:" in strip_comment(x).lower().replace(" ", "") for x in rule_lines) or any(
        strip_comment(x).strip().lower().startswith("if:") for x in rule_lines[1:]
    )


def _depth(line: str) -> int:
    """Net parentheses one comment-stripped line opens, outside /regexes/."""
    depth = 0
    in_re = False
    prev = ""
    for c in line:
        if in_re:
            if c == "/" and prev != "\\":
                in_re = False
        elif c == "/" and (prev == "" or prev in "(,: \t"):
            in_re = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c not in " \t":
            prev = c
    return depth


def lines(raw_lines: Sequence[str]) -> list[str]:
    """Group lines and return the logical rules' text."""
    return [lg.text for lg in group(raw_lines)]
