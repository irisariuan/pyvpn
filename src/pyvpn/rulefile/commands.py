"""Bodies of ``pyvpn rules check/test/import/export`` (stream A wires them into the CLI).

Each command is pure: it takes text / config objects and returns a
``CommandResult`` (exit code + output). File and daemon I/O stay in the CLI.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from pyvpn.config.models import Config, Policy
from pyvpn.match import PolicyMatcher, PolicyRules, RuleSet
from pyvpn.match.pattern import regex_engine
from pyvpn.match.policy import NEEDS_RE2, normalize_name
from pyvpn.match.ruleset import Result
from pyvpn.rulefile.file import ParseResult, RuleFile, format_file, parse_text


@dataclass(frozen=True)
class CommandResult:
    code: int  # 0 ok, 1 problems found
    output: str


def _issues(path: str, r: ParseResult) -> list[str]:
    out = [f"{path}:{e.line}: error: {e.message}" for e in r.errors]
    out += [f"{path}:{w.line}: warning: {w.message}" for w in r.warnings]
    return out


def check(text: str, path: str = "<rules>", convert: bool = False) -> CommandResult:
    """``pyvpn rules check FILE``: report bad lines of a ``.rules`` file."""
    r = parse_text(text, convert=convert)
    lines = _issues(path, r)
    pr = PolicyRules.build(0, path, [*r.file.domains])
    lines += [f"{path}: warning: not supported by pyvpn yet: {u}" for u in pr.unsupported()]
    if regex_engine() != "re2":
        lines += [f"{path}: warning: {NEEDS_RE2}: {raw}" for _, raw in pr.needs_re2]
    f = r.file
    n_rules = sum(1 for d in f.domains if not d.startswith("#"))
    summary = f"{path}: {n_rules} domain rules, {len(f.asns)} ASNs, {len(f.cidrs)} CIDRs"
    if r.errors:
        summary += f", {len(r.errors)} errors"
    return CommandResult(1 if r.errors else 0, "\n".join([*lines, summary]) + "\n")


def check_config(config: Config) -> CommandResult:
    """``pyvpn rules check`` without a file: the config's policy rules.

    Rules the daemon refuses to activate are errors; regexes without RE2 are
    warnings (installing ``google-re2`` makes them activatable).
    """
    lines = []
    bad = False
    for i, p in enumerate(config.policies, start=1):
        if not p.domains:
            continue
        pr = PolicyRules.build(i, p.name, p.domains)
        for e in pr.errors:
            bad = True
            lines.append(f"policy {p.name!r} rule {e.index + 1}: error: {e.error} ({e.rule})")
        for u in pr.unsupported():
            bad = True
            lines.append(
                f"policy {p.name!r}: error: not supported by pyvpn yet, "
                f"the daemon refuses to activate it: {u}"
            )
        if regex_engine() != "re2":
            lines += [
                f"policy {p.name!r} rule {j + 1}: warning: {NEEDS_RE2} ({raw})"
                for j, raw in pr.needs_re2
            ]
    lines.append("errors found" if bad else "ok")
    return CommandResult(1 if bad else 0, "\n".join(lines) + "\n")


def describe(r: Result) -> str:
    """One line explaining a ``RuleSet.match_any`` result."""
    if r.excluded:
        return f"excluded by {r.excluded} (name {r.name})"
    if not r.matched:
        return "no match"
    via = f" (name {r.name})"
    if r.drop:
        return f"drop by {r.rule}{via}"
    if r.session:
        return f"session by {r.rule}{via}"
    if r.route:
        return f"route/drop session by {r.rule}{via}"
    if r.cond:
        return f"route (if: condition) by {r.rule}{via}"
    return f"route by {r.rule}{via}"


def explain_rules(rules: Sequence[str], names: Sequence[str]) -> CommandResult:
    """``pyvpn rules test FILE NAME [CNAME...]``: how a rule list treats a lookup.

    ``names`` is the query name followed by its CNAME chain.
    """
    rs, errs = RuleSet.compile(list(rules))
    chain = [normalize_name(n) for n in names]
    lines = [f"rule {e.index + 1}: error: {e.error}" for e in errs]
    r = rs.match_any(*chain)
    lines.append(f"{' -> '.join(chain)}: {describe(r)}")
    return CommandResult(0 if r.matched and not r.drop else 1, "\n".join(lines) + "\n")


def explain_config(config: Config, names: Sequence[str]) -> CommandResult:
    """``pyvpn rules test NAME [CNAME...]``: which policy a lookup goes to."""
    d = PolicyMatcher.from_config(config).explain(*names)
    chain = " -> ".join(normalize_name(n) for n in names)
    lines = [f"skipped policy {p!r}: excluded by {rule}" for p, rule in d.excluded_by]
    lines += [
        f"skipped policy {p!r}: per-device rule {rule} matched; not supported yet, "
        "the daemon refuses to activate this config"
        for p, rule in d.skipped
    ]
    if d.action == "route":
        lines.append(f"{chain}: policy {d.policy!r} ({describe(d.result)})")
    elif d.action == "drop":
        lines.append(f"{chain}: claimed by policy {d.policy!r} ({describe(d.result)})")
    else:
        lines.append(f"{chain}: no policy (default route)")
    return CommandResult(0 if d.action == "route" else 1, "\n".join(lines) + "\n")


def import_rules(text: str, path: str = "<rules>") -> tuple[CommandResult, RuleFile]:
    """``pyvpn rules import FILE``: convert AdGuard/hosts/dnsmasq/.rules text
    to canonical ``.rules``. Returns the text and the parsed file (the CLI may
    add it to a policy with ``policy_entries``)."""
    r = parse_text(text, convert=True)
    return CommandResult(1 if r.errors else 0, format_file(r.file)), r.file


def import_notes(text: str, path: str = "<rules>") -> str:
    """The messages ``import_rules`` would report (for stderr)."""
    r = parse_text(text, convert=True)
    return "\n".join([*_issues(path, r), f"{path}: converted {r.converted} lines"]) + "\n"


def policy_entries(f: RuleFile) -> tuple[str, ...]:
    """A rule file as ``Policy.domains`` entries (comments dropped)."""
    return (
        *(d for d in f.domains if not d.startswith("#")),
        *(f"asn:{a}" for a in f.asns),
        *(f"cidr:{c}" for c in f.cidrs),
    )


def policy_file(policy: Policy) -> RuleFile:
    """A policy's destination rules as a rule file (canonical; bad entries dropped)."""
    f = parse_text("\n".join(policy.domains)).file
    f.name = policy.name
    return f


def export_policy(policy: Policy) -> CommandResult:
    """``pyvpn rules export POLICY``: a policy's rules as ``.rules`` text."""
    return CommandResult(0, format_file(policy_file(policy)))
