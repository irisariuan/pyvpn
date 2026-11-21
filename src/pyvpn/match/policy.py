"""The ``RuleMatcher`` (services.py) built from a config's destination rules.

A policy's ``domains`` hold snake rules (see ``pattern``) plus ``asn:N`` and
``cidr:X`` / ``ip:X`` entries (PLAN.md §3.4). Policies are tried in config
order and the first one whose rules route a name wins.

Per policy, as in snake: ``!rule`` exempts a name from that policy (later
policies are still tried); ``drop:`` claims the name for the policy but does
not route it (blocking needs a drop set in the backend, not built yet);
``build_matcher`` refuses to activate ``drop:`` and per-device rules, and,
without ``google-re2``, rules that need RE2 (``Pattern.needs_re2``);
``session:``, ``route:`` and ``drop[...]:`` sessions are per device in snake
and not supported here yet (PLAN.md §4): they route nothing and ``check``
reports them. The names in an ``if:`` condition are routed like plain rules,
as snake does.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Literal

from pyvpn.config.models import Config, Policy
from pyvpn.match.asn import AsnCache
from pyvpn.match.pattern import RuleError, parse_asn, parse_cidr, regex_engine
from pyvpn.match.route import group
from pyvpn.match.ruleset import LineError, Result, RuleSet
from pyvpn.services import RuleMatcherFactory
from pyvpn.state import DestSet

AsnResolver = Callable[[int], Iterable[str]]
"""ASN -> announced prefixes, e.g. ``AsnCache.cached`` (must not block long)."""

Action = Literal["route", "drop", "none"]


NEEDS_RE2 = (
    "regexes and complex wildcards need the google-re2 package to match in bounded "
    "time; install it with: pip install 'snakevpn[re2]'"
)


class RuleConfigError(ValueError):
    """A config's destination rules cannot be activated as they are."""


def normalize_name(name: str) -> str:
    """A DNS name as rules compare it: lowercase, no trailing dot."""
    return name.strip().lower().removesuffix(".")


def _has_prefix(s: str, p: str) -> bool:
    return s[: len(p)].lower() == p


@dataclass
class PolicyRules:
    """One policy's destination rules, compiled."""

    policy_id: int
    name: str
    rules: RuleSet
    asns: tuple[int, ...] = ()
    cidrs: tuple[str, ...] = ()
    errors: tuple[LineError, ...] = ()  # index = position in the policy's domains
    # (position, rule) of rules that need RE2 to match in bounded time
    needs_re2: tuple[tuple[int, str], ...] = ()
    # The policy has neither app selectors nor exclusions, so its rules apply
    # to every process (a stub of any policy may pick it).
    any_process: bool = True

    @classmethod
    def build(cls, policy_id: int, name: str, entries: Sequence[str]) -> PolicyRules:
        domain_lines: list[str] = []
        where: list[int] = []  # domain_lines index -> entries index
        asns: list[int] = []
        cidrs: list[str] = []
        errors: list[LineError] = []
        for lg in group(list(entries)):
            text = lg.text.strip()
            try:
                if _has_prefix(text, "asn:"):
                    n = parse_asn(text[4:].split("#", 1)[0])
                    if n not in asns:
                        asns.append(n)
                    continue
                if _has_prefix(text, "cidr:") or _has_prefix(text, "ip:"):
                    c = parse_cidr(text.partition(":")[2].split("#", 1)[0])
                    if c not in cidrs:
                        cidrs.append(c)
                    continue
            except RuleError as e:
                errors.append(LineError(lg.first, lg.text, str(e)))
                continue
            domain_lines.append(lg.text)
            where.append(lg.first)
        rules, errs = RuleSet.compile(domain_lines)
        errors.extend(LineError(where[e.index], e.rule, e.error) for e in errs)
        errors.sort(key=lambda e: e.index)
        slow = tuple((where[i], raw) for i, raw in rules.needs_re2)
        return cls(policy_id, name, rules, tuple(asns), tuple(cidrs), tuple(errors), slow)

    def unsupported(self) -> list[str]:
        """Rules that parse but pyvpn does not act on yet."""
        r = self.rules
        out = [p.raw for p in r.session]
        out += [rt.raw for rt in r.routes]
        out += [p.raw for p in r.drop]
        out += [f"drop:asn:{a}" for a in r.drop_asns]
        out += [f"drop:cidr:{c}" for c in r.drop_cidrs]
        return out

    def dest_set(self, asn_prefixes: AsnResolver | None = None) -> DestSet:
        v4: set[IPv4Network] = set()
        v6: set[IPv6Network] = set()
        nets = list(self.cidrs)
        if asn_prefixes is not None:
            for a in self.asns:
                nets.extend(asn_prefixes(a))
        for c in nets:
            try:
                net = ip_network(c, strict=False)
            except ValueError:
                continue
            (v4 if isinstance(net, IPv4Network) else v6).add(net)  # type: ignore[arg-type]
        return DestSet(self.policy_id, frozenset(v4), frozenset(v6))


@dataclass(frozen=True)
class Decision:
    """Which policy a lookup belongs to, and why."""

    policy_id: int | None = None
    policy: str = ""
    action: Action = "none"  # route: send through the policy; drop: claimed, not routed
    result: Result = field(default_factory=Result)
    # policies whose exclusions vetoed the name before the decision
    excluded_by: tuple[tuple[str, str], ...] = ()
    # policies passed over because an unsupported per-device rule matched
    skipped: tuple[tuple[str, str], ...] = ()


class PolicyMatcher:
    """``RuleMatcher`` for a config: first policy whose rules route a name."""

    def __init__(
        self, policies: Sequence[PolicyRules], asn_prefixes: AsnResolver | None = None
    ) -> None:
        self.policies = list(policies)
        self._asn_prefixes = asn_prefixes

    @classmethod
    def from_config(cls, config: Config, asn_prefixes: AsnResolver | None = None) -> PolicyMatcher:
        return cls(
            [
                replace(
                    PolicyRules.build(i, p.name, p.domains),
                    any_process=not p.apps and not p.exclude_apps,
                )
                for i, p in enumerate(config.policies, start=1)
                if p.domains
            ],
            asn_prefixes,
        )

    def scoped(self, policy_id: int) -> PolicyMatcher:
        """The matcher for DNS asked through ``policy_id``'s stub.

        Only policies that apply to that stub's apps take part: the policy
        itself and policies without app selectors or exclusions. Otherwise an
        earlier app policy with the same domain (Firefox's) would win a name
        asked by a later one's apps (Chrome's), and the answer's addresses
        would never reach the asking policy's set. A policy with
        ``exclude_apps`` only takes part for its own stub: the matcher cannot
        tell which app is asking, so it must not let a policy win a lookup
        from an app it excludes.
        """
        return PolicyMatcher(
            [pr for pr in self.policies if pr.policy_id == policy_id or pr.any_process],
            self._asn_prefixes,
        )

    def explain(self, *names: str) -> Decision:
        """Decide for a query name followed by its CNAME chain."""
        chain = [n for n in (normalize_name(x) for x in names) if n]
        excluded: list[tuple[str, str]] = []
        skipped: list[tuple[str, str]] = []
        for pr in self.policies:
            r = pr.rules.match_any(*chain)
            if r.excluded:
                excluded.append((pr.name, r.excluded))
                continue
            if not r.matched:
                continue
            if r.drop:
                return Decision(pr.policy_id, pr.name, "drop", r, tuple(excluded), tuple(skipped))
            if r.session or r.route:
                skipped.append((pr.name, r.rule))  # per-device sessions: not supported yet
                continue
            return Decision(pr.policy_id, pr.name, "route", r, tuple(excluded), tuple(skipped))
        return Decision(excluded_by=tuple(excluded), skipped=tuple(skipped))

    def match_chain(self, *names: str) -> int | None:
        d = self.explain(*names)
        return d.policy_id if d.action == "route" else None

    def match(self, domain: str) -> int | None:
        return self.match_chain(domain)

    def static_sets(self) -> list[DestSet]:
        """asn:/cidr: destinations per policy (ASNs via the resolver, if any)."""
        out = []
        for pr in self.policies:
            ds = pr.dest_set(self._asn_prefixes)
            if ds:
                out.append(ds)
        return out

    def asns(self) -> list[int]:
        """Every ASN the config refers to (for refreshing the cache)."""
        return list(dict.fromkeys(a for pr in self.policies for a in pr.asns))

    def problems(self) -> list[str]:
        """Why these rules cannot be activated; empty when they can.

        Rejected: rules that do not parse (a typo would leave traffic
        outside its policy), ``drop:`` rules (they claim a name but nothing
        blocks it yet, so it would take the host route), per-device rules
        (``session:``, ``route:``, ``if:`` with ``then:``/``else:``: they
        route nothing and are checked before plain rules, so they would hide
        them), ASNs with no prefixes (the policy would silently match
        nothing) and, without the ``google-re2`` package, regexes and
        complex wildcards (Python's ``re`` can take exponential time on a
        crafted name, on the DNS path).
        """
        out: list[str] = []
        re2 = regex_engine() == "re2"
        for pr in self.policies:
            where = f"policy {pr.name!r}"
            out += [f"{where} rule {e.index + 1}: {e.error}: {e.rule}" for e in pr.errors]
            if not re2:
                out += [f"{where} rule {i + 1}: {NEEDS_RE2}: {raw}" for i, raw in pr.needs_re2]
            for raw in pr.unsupported():
                if raw.lower().startswith("drop:"):
                    out.append(f"{where}: drop: rules are not enforced yet: {raw}")
                else:
                    out.append(f"{where}: per-device rules are not supported yet: {raw}")
            for a in pr.asns:
                if self._asn_prefixes is None:
                    out.append(f"{where}: asn:{a} needs the ASN cache")
                else:
                    out += asn_problems(where, a, self._asn_prefixes(a))
        return out

    def bases(self, policy_id: int) -> list[str]:
        """Domain suffixes whose DNS the policy's rules need (see RuleSet.bases)."""
        for pr in self.policies:
            if pr.policy_id == policy_id:
                return pr.rules.bases()
        return []


def asn_problems(where: str, asn: int, prefixes: Iterable[str]) -> list[str]:
    """Why cached ``prefixes`` for ``asn`` cannot be activated: none at all, or
    entries that are not networks (they would be dropped silently)."""
    nets = list(prefixes)
    if not nets:
        return [f"{where}: asn:{asn} has no cached prefixes; refresh the ASN cache"]
    out = []
    for c in nets:
        try:
            ip_network(c, strict=False)
        except ValueError:
            out.append(f"{where}: asn:{asn} cached prefix {c!r} is not a network")
    return out


def build_matcher(config: Config, asn_cache: AsnCache | None = None) -> PolicyMatcher:
    """``RuleMatcherFactory``: the matcher the daemon activates.

    ASN prefixes come from ``asn_cache`` (cached only, never fetched). Raises
    ``RuleConfigError`` listing every rule that cannot be activated, so a
    config load or reload fails instead of routing less than configured.
    ``pyvpn rules check`` uses the lenient ``PolicyMatcher.from_config``.
    """
    matcher = PolicyMatcher.from_config(config, asn_cache.cached if asn_cache else None)
    problems = matcher.problems()
    if problems:
        raise RuleConfigError("cannot activate destination rules:\n  " + "\n  ".join(problems))
    return matcher


def matcher_factory(asn_cache: AsnCache | None) -> RuleMatcherFactory:
    """A ``RuleMatcherFactory`` that resolves ASNs from ``asn_cache``."""

    def factory(config: Config) -> PolicyMatcher:
        return build_matcher(config, asn_cache)

    return factory


def policy_rules(policy_id: int, policy: Policy) -> PolicyRules:
    return PolicyRules.build(policy_id, policy.name, policy.domains)
