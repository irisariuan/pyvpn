"""Which ``exclude_apps`` selectors pyvpn can enforce (PLAN.md §3.3).

OS-agnostic: the daemon calls :func:`unsupported_exclusions` before it binds
a config, and ``pyvpn test`` reports the same problems.

- A policy **with apps**: ``exclude_apps`` filter placement. The process
  watcher never places an excluded process in the policy's cgroup, but it
  never moves one out either: a process that inherited the cgroup (started
  from an app already in the policy) stays routed. Moving it out would
  grant an exemption that outlives the next ``exec``, so a new program
  could run outside the policy's kill switch. :func:`exclusion_warnings`
  says so in ``pyvpn test``.
- A policy with destination rules and **no apps** (``any_process``) can only
  exempt by ``uid`` / ``user`` today (``exclude_uids``, a static nft match).
  ``exe`` / ``name`` are deferred: an exemption granted to a process by its
  executable outlives an ``exec``, so a new program could open a socket
  before it is revoked. ``unit`` / ``flatpak`` / ``snap`` are deferred too:
  their cgroups come and go with the app, and the backend refuses to apply
  a plan that lists a cgroup that does not exist, so listing one could stop
  a later apply (a target going down) from taking effect.
"""

from __future__ import annotations

import pwd
from collections.abc import Iterable, Sequence

from pyvpn.config.models import AppGroup, AppRef, AppSelector, Config, Policy

# Selector fields a destination-only policy can exempt by.
ANY_PROCESS_FIELDS = frozenset({"uid", "user"})


def expand(refs: Iterable[AppRef], groups: Sequence[AppGroup]) -> list[AppSelector]:
    """Selectors of ``refs``, with ``group:<name>`` references expanded."""
    group_map = {group.name: group.apps for group in groups}
    selectors: list[AppSelector] = []
    for ref in refs:
        if isinstance(ref, AppSelector):
            selectors.append(ref)
        else:
            selectors.extend(group_map.get(ref.removeprefix("group:"), ()))
    return selectors


def selector_field(selector: AppSelector) -> str:
    return next(iter(selector.model_dump(exclude_none=True)))


def unsupported_exclusions(policy: Policy, groups: Sequence[AppGroup]) -> list[str]:
    """Why ``policy``'s ``exclude_apps`` cannot be enforced, or ``[]``."""
    if not policy.exclude_apps:
        return []
    problems: list[str] = []
    for selector in expand(policy.exclude_apps, groups):
        if selector.user is not None:
            try:
                pwd.getpwnam(selector.user)
            except KeyError:
                problems.append(
                    f"policy {policy.name!r}: exclude_apps user: {selector.user!r} does not exist"
                )
                continue
        field = selector_field(selector)
        if field in ANY_PROCESS_FIELDS:
            continue
        if policy.apps:
            # A uid/user app selector is a raw nft skuid match. A name/exe/...
            # exclusion cannot be subtracted from it, so refuse the combination.
            app_selectors = expand(policy.apps, groups)
            if not any(
                selector_field(app_selector) in ANY_PROCESS_FIELDS for app_selector in app_selectors
            ):
                continue
            value = getattr(selector, field)
            problems.append(
                f"policy {policy.name!r}: exclude_apps {field}: {value!r} cannot be "
                "combined with a uid/user app selector; exclude it by uid or user"
            )
            continue
        value = getattr(selector, field)
        problems.append(
            f"policy {policy.name!r}: exclude_apps {field}: {value!r} is not supported on a "
            "policy without apps yet; exclude it by uid or user (for example run the VPN "
            "client as its own user)"
        )
    return problems


def config_exclusion_problems(config: Config) -> list[str]:
    """:func:`unsupported_exclusions` for every policy in ``config``."""
    return [
        problem
        for policy in config.policies
        for problem in unsupported_exclusions(policy, config.app_groups)
    ]


def exclusion_warnings(config: Config) -> list[str]:
    """Exclusions that are enforced only in part (policies with apps)."""
    return [
        f"policy {policy.name!r}: exclude_apps only keep matching processes from being "
        "placed; an excluded program started from a process already in this policy "
        "stays routed by it"
        for policy in config.policies
        if policy.apps
        and policy.exclude_apps
        and not unsupported_exclusions(policy, config.app_groups)
    ]
