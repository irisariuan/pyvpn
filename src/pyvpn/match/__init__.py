"""snake's domain rule language (port of snake ``internal/match``).

See ``pattern`` for the rule syntax, ``route`` for conditional rules,
``ruleset`` for compiled lists and ``policy`` for the daemon's ``RuleMatcher``.
"""

from pyvpn.match.opts import OptionError, Opts
from pyvpn.match.pattern import (
    Kind,
    Pattern,
    RuleError,
    is_route,
    normalize,
    parse,
    parse_asn,
    parse_cidr,
    strip_comment,
)
from pyvpn.match.policy import (
    Decision,
    PolicyMatcher,
    PolicyRules,
    RuleConfigError,
    build_matcher,
    matcher_factory,
)
from pyvpn.match.route import (
    Action,
    CondHit,
    Expr,
    Route,
    convert_legacy,
    group,
    is_legacy_route,
    parse_route,
)
from pyvpn.match.ruleset import LineError, Result, RuleSet, Step

__all__ = [
    "Action",
    "CondHit",
    "Decision",
    "Expr",
    "Kind",
    "LineError",
    "OptionError",
    "Opts",
    "Pattern",
    "PolicyMatcher",
    "PolicyRules",
    "Result",
    "Route",
    "RuleConfigError",
    "RuleError",
    "RuleSet",
    "Step",
    "build_matcher",
    "convert_legacy",
    "group",
    "is_legacy_route",
    "is_route",
    "matcher_factory",
    "normalize",
    "parse",
    "parse_asn",
    "parse_cidr",
    "parse_route",
    "strip_comment",
]
