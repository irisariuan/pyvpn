"""Build the ``table inet pyvpn`` ruleset as nft JSON, without running nft.

Everything here is pure: a ``RoutingPlan`` goes in, a dict ready for
``nft -j -f -`` comes out. Golden files in ``tests/netfilter/`` pin the output.

Packet path (PLAN.md §3)::

    hook output, prio -100 (nat)    chain dns
        socket already carries a pyvpn mark (the daemon's own DNS stub
        upstream sockets, SO_MARK) -> return, so queries never loop
        <policy apps> port 53 udp/tcp -> redirect to the family's loopback stub

    hook output, prio -90 (route)   chain output
        socket in a pyvpn.slice/<child> cgroup that is not one of the
        loaded ones (re-created, so its id changed) -> reject
        LAN / loopback / multicast destination -> accept unchanged
        socket already carries a pyvpn mark -> accept unchanged
        conntrack mark of policy P -> enforce P's current leak rules and route
            (reject while P is a kill switch)
        <policy P apps> -> jump p<P>

    chain p<P>        DoT / DoH rejects (anything that bypasses the stub)
                      [daddr in @p<P>_v4 / @p<P>_v6] -> goto p<P>_route
    chain p<P>_route  IPv6 / QUIC rejects, then
                      route unreachable -> reject (kill switch)
                      otherwise mark P, save it in conntrack, accept

    hook postrouting, prio 0 (filter) chain egress
        managed mark P -> drop unless this family can use the actual interface

    hook postrouting, prio 100 (nat)  chain masq
        mark P out of P's interface -> masquerade

    hook prerouting, prio -150        chain restore
        conntrack mark P -> mark P (replies keep the mark, e.g. for rp_filter)

Policies with ``isolation: netns`` (PLAN.md §3.6) are forwarded, not
classified by socket::

    hook prerouting, prio -150        chain restore
        iifname pyvpn-h<P> -> mark P (and conntrack mark P)

    hook forward, prio 0 (filter)     chain forward
        iifname pyvpn-h<P> -> jump n<P>
        oifname pyvpn-h<P>, established/related -> accept (replies)
        anything else from or to a namespace subnet -> drop
        new connections arriving on a target pyvpn enabled forwarding on -> drop

    chain n<P>        IPv6, port 53 (DNS goes to the in-namespace relay),
                      DoT / DoH / QUIC as configured, then
                      route unreachable -> reject (kill switch)
                      route dev -> drop unless leaving via P's interface
                      otherwise accept

    egress: replies to pyvpn-h<P> are accepted before the interface check;
    masq: the namespace subnet is masqueraded on any interface but a veth.

The dns chain runs before the route chain so a mark set by the route chain
never hides an app's query from the redirect; only socket marks exempt.

Marks are written with ``POLICY_MARK_MASK``: bits outside it (marks from VPN
apps, firewalld, ...) are kept. Leak rules for DoT and DoH apply to every
packet of the policy's apps (they bypass the stub, which is how the policy
learns destinations); IPv6 and QUIC rules apply to the traffic the policy
governs (all of it, or only its destinations).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from ipaddress import IPv4Network, IPv6Network
from typing import Any

from pyvpn.constants import (
    CGROUP_ROOT,
    FWMARK_BASE,
    FWMARK_MASK,
    NETNS_RANGE,
    NFT_TABLE,
    netns_host_veth,
    netns_subnet,
    parse_excluded_cgroup,
)
from pyvpn.netfilter.doh import DOH_V4, DOH_V6
from pyvpn.routing.plan import POLICY_MARK_MASK, RoutePlan, build_route_plan
from pyvpn.state import DestSet, PolicyPlan, RoutingPlan

Json = dict[str, Any]
Expr = list[Json]

FAMILY = "inet"
ROUTE_GUARD_TABLE = f"{NFT_TABLE}_guard"
NETNS_TABLE = f"{NFT_TABLE}_ns"  # inside each policy namespace
FORWARD_PRIORITY = 0  # NF_IP_PRI_FILTER
DNS_PRIORITY = -100  # NF_IP_PRI_NAT_DST
ROUTE_PRIORITY = -90  # after dns, so app marks never exempt a query
GUARD_PRIORITY = -80  # after the route chain has classified outgoing packets
EGRESS_PRIORITY = 0  # inspect the selected interface before source NAT
MASQ_PRIORITY = 100  # NF_IP_PRI_NAT_SRC
RESTORE_PRIORITY = -150  # NF_IP_PRI_MANGLE

_KEEP_BITS = ~POLICY_MARK_MASK & 0xFFFF_FFFF

LAN_V4: tuple[IPv4Network, ...] = tuple(
    IPv4Network(a)
    for a in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
    )
)
LAN_V6: tuple[IPv6Network, ...] = tuple(
    IPv6Network(a) for a in ("::1/128", "fc00::/7", "fe80::/10", "ff00::/8")
)

_REJECT: Json = {"reject": {"type": "icmpx", "expr": "admin-prohibited"}}
_ACCEPT: Json = {"accept": None}
_DROP: Json = {"drop": None}


def set_name(policy_id: int, version: int) -> str:
    """Name of a policy's destination set, e.g. ``p3_v4``."""
    return f"p{policy_id}_v{version}"


def build_ruleset(
    plan: RoutingPlan,
    *,
    idle_exclusions: Iterable[str] = (),
    forwarding_guard: Iterable[str] = (),
) -> Json:
    """Replace ``table inet pyvpn`` with the state described by ``plan``.

    ``forwarding_guard`` names the target interfaces on which pyvpn turned
    IPv4 forwarding on so namespace replies can pass. New connections that
    arrive on them and would be forwarded are dropped, so the host does not
    become a router for that link.

    ``idle_exclusions`` are existing top-level exclusion cgroups
    (``pyvpn.slice/x-<hex>``) that no binding lists yet, for example while
    the app manager revalidates them after a reload. They are known to the
    stale-cgroup check, so their members are governed like any other
    process instead of rejected; they are not exempt from any policy.

    The ``add`` / ``delete`` / ``add`` prologue makes one nft transaction
    that works whether or not the table exists, and either installs the
    whole new table or leaves the old one untouched.
    """
    routes = build_route_plan(plan)
    cmds: list[Json] = [*_table_reset(), {"add": {"table": _table()}}]
    cmds += _sets(plan)
    stale_checks = _stale_cgroup_rules(plan, idle_exclusions)
    cmds += _chains()
    isolated = [p for p in plan.policies if p.isolation == "netns"]
    guard = sorted(set(forwarding_guard))
    if isolated or guard:
        cmds.append(_base_chain("forward", "filter", "forward", FORWARD_PRIORITY))
        cmds += [{"add": {"chain": {**_ref(), "name": f"n{p.policy_id}"}}} for p in isolated]
    if stale_checks:
        cmds.append({"add": {"chain": {**_ref(), "name": "check_cgroup"}}})
    for policy in plan.policies:
        cmds += _policy_chains(policy)

    rules: list[tuple[str, Expr]] = []
    rules += _dns_rules(plan)
    rules += stale_checks
    rules += _output_rules(plan)
    for policy in plan.policies:
        rules += _policy_rules(policy)
    rules += _netns_egress_rules(isolated)
    rules += _egress_rules(routes)
    rules += _masq_rules(plan)
    rules += _restore_rules(plan)
    if isolated or guard:
        rules += _forward_rules(isolated, guard)
    cmds += [{"add": {"rule": {**_ref(), "chain": chain, "expr": expr}}} for chain, expr in rules]
    return {"nftables": cmds}


def build_set_update(dests: DestSet) -> Json:
    """Add ``dests`` to its policy's sets (``Backend.add_to_set``)."""
    cmds: list[Json] = []
    for version, nets in ((4, dests.v4), (6, dests.v6)):
        if nets:
            elem = _elements(nets)
            name = set_name(dests.policy_id, version)
            cmds.append({"add": {"element": {**_ref(), "name": name, "elem": elem}}})
    return {"nftables": cmds}


def build_teardown() -> Json:
    """Remove ``table inet pyvpn`` (a no-op when it is absent)."""
    return {"nftables": _table_reset()}


def build_route_guard(*, enabled: bool) -> Json:
    """Keep marked packets from egress while kernel routes are being replaced.

    Packets forwarded from a policy namespace are dropped as well, so nothing
    leaves an isolated namespace while routes and rules change.
    """
    name = ROUTE_GUARD_TABLE
    cmds = _table_reset(name)
    if enabled:
        cmds.extend(
            (
                {"add": {"table": _table(name)}},
                _base_chain("output", "filter", "output", GUARD_PRIORITY, table=name),
                {
                    "add": {
                        "rule": {
                            **_ref(name),
                            "chain": "output",
                            "expr": [_any_pyvpn_mark(), _REJECT],
                        }
                    }
                },
                _base_chain("forward", "filter", "forward", GUARD_PRIORITY, table=name),
                {
                    "add": {
                        "rule": {
                            **_ref(name),
                            "chain": "forward",
                            "expr": [_saddr_in_netns(), _DROP],
                        }
                    }
                },
            )
        )
    return {"nftables": cmds}


def build_netns_ruleset() -> Json:
    """``table inet pyvpn_ns`` inside a policy namespace.

    Every DNS query, including ones to hard-coded resolvers and to a
    loopback resolver such as ``127.0.0.53``, is redirected to the
    namespace's own port 53, where the daemon relays it to the policy's stub.
    """
    name = NETNS_TABLE
    redirect = {"redirect": {"port": 53}}
    return {
        "nftables": [
            *_table_reset(name),
            {"add": {"table": _table(name)}},
            _base_chain("dns", "nat", "output", DNS_PRIORITY, table=name),
            {
                "add": {
                    "rule": {
                        **_ref(name),
                        "chain": "dns",
                        "expr": [*_l4(("tcp", "udp"), 53), redirect],
                    }
                }
            },
        ]
    }


# --- table, sets, chains -------------------------------------------------------


def _table(name: str = NFT_TABLE) -> Json:
    return {"family": FAMILY, "name": name}


def _ref(name: str = NFT_TABLE) -> Json:
    return {"family": FAMILY, "table": name}


def _table_reset(name: str = NFT_TABLE) -> list[Json]:
    return [{"add": {"table": _table(name)}}, {"delete": {"table": _table(name)}}]


def _set(name: str, version: int, nets: Iterable[IPv4Network | IPv6Network]) -> Json:
    body: Json = {
        **_ref(),
        "name": name,
        "type": "ipv4_addr" if version == 4 else "ipv6_addr",
        "flags": ["interval"],
        "auto-merge": True,
    }
    elem = _elements(nets)
    if elem:
        body["elem"] = elem
    return {"add": {"set": body}}


def _sets(plan: RoutingPlan) -> list[Json]:
    out = [_set("lan_v4", 4, LAN_V4), _set("lan_v6", 6, LAN_V6)]
    if any(p.leak.block_doh for p in plan.policies):
        out += [_set("doh_v4", 4, DOH_V4), _set("doh_v6", 6, DOH_V6)]
    for p in plan.policies:
        if p.dests is not None:
            out.append(_set(set_name(p.policy_id, 4), 4, p.dests.v4))
            out.append(_set(set_name(p.policy_id, 6), 6, p.dests.v6))
    return out


def _base_chain(name: str, kind: str, hook: str, prio: int, *, table: str = NFT_TABLE) -> Json:
    chain = {**_ref(table), "name": name, "type": kind, "hook": hook, "prio": prio}
    return {"add": {"chain": {**chain, "policy": "accept"}}}


def _chains() -> list[Json]:
    base = _base_chain
    return [
        base("dns", "nat", "output", DNS_PRIORITY),
        base("output", "route", "output", ROUTE_PRIORITY),
        base("egress", "filter", "postrouting", EGRESS_PRIORITY),
        base("masq", "nat", "postrouting", MASQ_PRIORITY),
        base("restore", "filter", "prerouting", RESTORE_PRIORITY),
    ]


def _policy_chains(policy: PolicyPlan) -> list[Json]:
    pid = policy.policy_id
    return [{"add": {"chain": {**_ref(), "name": name}}} for name in (f"p{pid}", f"p{pid}_route")]


def _elements(nets: Iterable[IPv4Network | IPv6Network]) -> list[Any]:
    out: list[Any] = []
    for net in sorted(nets, key=lambda n: (n.network_address, n.prefixlen)):
        if net.prefixlen == net.max_prefixlen:
            out.append(str(net.network_address))
        else:
            out.append({"prefix": {"addr": str(net.network_address), "len": net.prefixlen}})
    return out


# --- expressions ---------------------------------------------------------------


def _meta(key: str) -> Json:
    return {"meta": {"key": key}}


def _match(left: Json, right: Any, op: str = "==") -> Json:
    return {"match": {"op": op, "left": left, "right": right}}


def _masked(key: Json, mask: int) -> Json:
    return {"&": [key, mask]}


def _mark_is(mark: int) -> Json:
    return _match(_masked(_meta("mark"), POLICY_MARK_MASK), mark)


def _ct_mark_is(mark: int) -> Json:
    return _match(_masked({"ct": {"key": "mark"}}, POLICY_MARK_MASK), mark)


def _set_mark(key: Json, mark: int) -> Json:
    return {"mangle": {"key": key, "value": {"|": [_masked(key, _KEEP_BITS), mark]}}}


def _any_pyvpn_mark() -> Json:
    return _match(_masked(_meta("mark"), FWMARK_MASK), FWMARK_BASE)


def _prefix(net: IPv4Network) -> Json:
    return {"prefix": {"addr": str(net.network_address), "len": net.prefixlen}}


def _saddr_in_netns() -> Json:
    return _match({"payload": {"protocol": "ip", "field": "saddr"}}, _prefix(NETNS_RANGE))


def _daddr_in_netns() -> Json:
    return _match({"payload": {"protocol": "ip", "field": "daddr"}}, _prefix(NETNS_RANGE))


def _daddr_in(version: int, name: str) -> Json:
    proto = "ip" if version == 4 else "ip6"
    return _match({"payload": {"protocol": proto, "field": "daddr"}}, f"@{name}")


def _l4(protos: Sequence[str], port: int) -> Expr:
    right: Any = protos[0] if len(protos) == 1 else {"set": list(protos)}
    return [
        _match(_meta("l4proto"), right),
        _match({"payload": {"protocol": "th", "field": "dport"}}, port),
    ]


def _selectors(policy: PolicyPlan) -> list[Expr]:
    """Match prefixes for the policy's processes (empty list: matches nothing)."""
    apps = policy.apps
    if apps.any_process:
        # Only packets from user processes: ``meta skuid`` does not match
        # kernel sockets, so a kernel tunnel's own encapsulated packets (e.g.
        # WireGuard to an endpoint inside a destination set) are never marked
        # back into the tunnel.
        return [[_match(_meta("skuid"), 0, ">=")]]
    out: list[Expr] = []
    for path in apps.cgroup_paths:
        clean = path.strip("/")
        level = len(clean.split("/"))
        out.append([_match({"socket": {"key": "cgroupv2", "level": level}}, clean)])
    if apps.uids:
        uids = sorted(set(apps.uids))
        right: Any = uids[0] if len(uids) == 1 else {"set": uids}
        out.append([_match(_meta("skuid"), right)])
    return out


# --- rules ---------------------------------------------------------------------


def _dns_rules(plan: RoutingPlan) -> list[tuple[str, Expr]]:
    rules: list[tuple[str, Expr]] = [("dns", [_any_pyvpn_mark(), {"return": None}])]
    for p in plan.policies:
        if p.dns_stub_port is None:
            continue
        redirect = {"redirect": {"port": p.dns_stub_port}}
        for sel in _selectors(p):
            rules.append(("dns", [*sel, *_l4(("tcp", "udp"), 53), redirect]))
    return rules


def _stale_cgroup_rules(
    plan: RoutingPlan, idle_exclusions: Iterable[str] = ()
) -> list[tuple[str, Expr]]:
    """Reject sockets in a ``pyvpn.slice`` child the ruleset does not know.

    ``socket cgroupv2`` compares cgroup ids resolved when the ruleset was
    loaded. A policy cgroup removed and created again has a new id, so its
    processes would miss the policy until the backend re-applies. Reject
    unknown children of the installed slice before the loopback exemption,
    so they cannot reach a local DNS forwarder either. Keep each comparison
    in its own rule so all policy slots fit within nft's per-rule limit.

    Exclusion cgroups (PLAN.md §3.3) are known too. A top-level
    ``pyvpn.slice/x-<hex>`` is its own level-2 child. A nested
    ``pyvpn.slice/p-Q/x-<hex>`` sits below policy Q's cgroup, so it passes
    only while ``pyvpn.slice/p-Q`` is known; otherwise it stays rejected.
    """
    prefix = CGROUP_ROOT + "/"
    children = {
        c.strip("/")
        for p in plan.policies
        for c in p.apps.cgroup_paths
        if c.strip("/").startswith(prefix) and c.strip("/").count("/") == 1
    }
    exclusions = [c for p in plan.policies for c in p.apps.exclude_cgroup_paths]
    for path in [*exclusions, *idle_exclusions]:
        decoded = parse_excluded_cgroup(path)
        if decoded is not None and decoded.app_policy_id is None:
            children.add(path)
    known = sorted(children)
    if not known:
        return []
    slice_match = _match({"socket": {"key": "cgroupv2", "level": 1}}, CGROUP_ROOT)
    rules: list[tuple[str, Expr]] = [
        ("output", [slice_match, {"jump": {"target": "check_cgroup"}}]),
    ]
    for child in known:
        child_match = _match({"socket": {"key": "cgroupv2", "level": 2}}, child)
        rules.append(("check_cgroup", [child_match, {"return": None}]))
    rules.append(("check_cgroup", [_REJECT]))
    return rules


def _output_rules(plan: RoutingPlan) -> list[tuple[str, Expr]]:
    rules: list[tuple[str, Expr]] = [
        ("output", [_daddr_in(4, "lan_v4"), _ACCEPT]),
        ("output", [_daddr_in(6, "lan_v6"), _ACCEPT]),
        ("output", [_any_pyvpn_mark(), _ACCEPT]),
    ]
    for p in plan.policies:
        if p.route == "unreachable":
            rules.append(("output", [_ct_mark_is(p.mark), _REJECT]))
        else:
            rules.append(("output", [_ct_mark_is(p.mark), {"jump": {"target": f"p{p.policy_id}"}}]))
    for p in plan.policies:
        for sel in _selectors(p):
            rules.append(("output", [*sel, {"jump": {"target": f"p{p.policy_id}"}}]))
    return rules


def _policy_rules(policy: PolicyPlan) -> list[tuple[str, Expr]]:
    pid = policy.policy_id
    head, route = f"p{pid}", f"p{pid}_route"
    leak = policy.leak
    rules: list[tuple[str, Expr]] = []

    if leak.block_dot:
        rules.append((head, [*_l4(("tcp", "udp"), 853), _REJECT]))
    if leak.block_doh:
        for version in (4, 6):
            rules.append(
                (head, [_daddr_in(version, f"doh_v{version}"), *_l4(("tcp", "udp"), 443), _REJECT])
            )
    goto = {"goto": {"target": route}}
    if policy.dests is None:
        rules.append((head, [goto]))
    else:
        # Keep the policy selected when the connection was first marked,
        # while applying the current leak rules before restoring that mark.
        rules.append((head, [_ct_mark_is(policy.mark), goto]))
        for version in (4, 6):
            rules.append((head, [_daddr_in(version, set_name(pid, version)), goto]))

    if leak.ipv6 == "block":
        rules.append((route, [_match(_meta("nfproto"), "ipv6"), _REJECT]))
    if leak.block_quic:
        rules.append((route, [*_l4(("udp",), 443), _REJECT]))
    if policy.route == "unreachable":
        rules.append((route, [_REJECT]))
    else:
        ct = {"ct": {"key": "mark"}}
        rules.append(
            (route, [_set_mark(_meta("mark"), policy.mark), _set_mark(ct, policy.mark), _ACCEPT])
        )
    return rules


def _egress_rules(routes: RoutePlan) -> list[tuple[str, Expr]]:
    """Enforce the policy table's egress even if another routing rule wins."""
    interfaces = {
        (route.version, route.table): route.interface
        for route in routes.routes
        if route.kind == "unicast"
    }
    out: list[tuple[str, Expr]] = []
    for rule in routes.rules:
        exprs = [_mark_is(rule.mark), _match(_meta("nfproto"), f"ipv{rule.version}")]
        interface = interfaces.get((rule.version, rule.table))
        if interface is not None:
            exprs.append(_match(_meta("oifname"), interface, "!="))
        out.append(("egress", [*exprs, _DROP]))
    return out


def _masq_rules(plan: RoutingPlan) -> list[tuple[str, Expr]]:
    rules: list[tuple[str, Expr]] = []
    for p in plan.policies:
        if p.route == "dev" and p.interface:
            oif = _match(_meta("oifname"), p.interface)
            rules.append(("masq", [_mark_is(p.mark), oif, {"masquerade": None}]))
    for p in plan.policies:
        if p.isolation == "netns" and p.route != "unreachable":
            # Covers the default-route fallback (route main) too; the forward
            # chain already decided which interface may be used.
            saddr = _match(
                {"payload": {"protocol": "ip", "field": "saddr"}},
                _prefix(netns_subnet(p.policy_id)),
            )
            veth = _match(_meta("oifname"), netns_host_veth(p.policy_id), "!=")
            rules.append(("masq", [saddr, veth, {"masquerade": None}]))
    return rules


def _restore_rules(plan: RoutingPlan) -> list[tuple[str, Expr]]:
    rules: list[tuple[str, Expr]] = [
        ("restore", [_ct_mark_is(p.mark), _set_mark(_meta("mark"), p.mark)]) for p in plan.policies
    ]
    for p in plan.policies:
        if p.isolation == "netns":
            # Everything from the namespace belongs to the policy: route it
            # through the policy table and let the egress check enforce it.
            iif = _match(_meta("iifname"), netns_host_veth(p.policy_id))
            ct = {"ct": {"key": "mark"}}
            rules.append(
                ("restore", [iif, _set_mark(_meta("mark"), p.mark), _set_mark(ct, p.mark)])
            )
    return rules


def _netns_egress_rules(isolated: Sequence[PolicyPlan]) -> list[tuple[str, Expr]]:
    """Replies to a namespace carry the restored mark but leave via its veth."""
    return [
        ("egress", [_match(_meta("oifname"), netns_host_veth(p.policy_id)), _ACCEPT])
        for p in isolated
    ]


def _forward_rules(isolated: Sequence[PolicyPlan], guard: Sequence[str]) -> list[tuple[str, Expr]]:
    rules: list[tuple[str, Expr]] = []
    for p in isolated:
        iif = _match(_meta("iifname"), netns_host_veth(p.policy_id))
        rules.append(("forward", [iif, {"jump": {"target": f"n{p.policy_id}"}}]))
    replies = _match({"ct": {"key": "state"}}, {"set": ["established", "related"]})
    for p in isolated:
        oif = _match(_meta("oifname"), netns_host_veth(p.policy_id))
        rules.append(("forward", [oif, replies, _ACCEPT]))
    # Unknown or stale veths, other namespaces, inbound connections.
    rules.append(("forward", [_saddr_in_netns(), _DROP]))
    rules.append(("forward", [_daddr_in_netns(), _DROP]))
    if guard:
        names: Any = guard[0] if len(guard) == 1 else {"set": list(guard)}
        rules.append(("forward", [_match(_meta("iifname"), names), _DROP]))
    for p in isolated:
        rules += _netns_policy_rules(p)
    return rules


def _netns_policy_rules(policy: PolicyPlan) -> list[tuple[str, Expr]]:
    chain = f"n{policy.policy_id}"
    leak = policy.leak
    rules: list[tuple[str, Expr]] = [
        # The namespace has no IPv6; never forward it, whatever leak.ipv6 says.
        (chain, [_match(_meta("nfproto"), "ipv6"), _DROP]),
        (chain, [_daddr_in_netns(), _DROP]),
        # DNS is redirected to the relay inside the namespace; a query that
        # still reaches the host bypassed it.
        (chain, [*_l4(("tcp", "udp"), 53), _DROP]),
    ]
    if leak.block_dot:
        rules.append((chain, [*_l4(("tcp", "udp"), 853), _REJECT]))
    if leak.block_doh:
        rules.append((chain, [_daddr_in(4, "doh_v4"), *_l4(("tcp", "udp"), 443), _REJECT]))
    if leak.block_quic:
        rules.append((chain, [*_l4(("udp",), 443), _REJECT]))
    if policy.route == "unreachable":
        rules.append((chain, [_REJECT]))
        return rules
    if policy.route == "dev" and policy.interface:
        rules.append((chain, [_match(_meta("oifname"), policy.interface, "!="), _DROP]))
    rules.append((chain, [_ACCEPT]))
    return rules
