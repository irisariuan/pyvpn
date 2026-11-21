"""Describe DNS policy configuration and stub readiness for the daemon's audit."""

from dataclasses import dataclass
from importlib.util import find_spec

from pyvpn.dns.upstream import upstream_endpoint
from pyvpn.state import PolicyPlan


@dataclass(frozen=True)
class DnsAudit:
    stub_listening: bool
    upstream_interface: str | None
    upstream_problem: str | None
    firefox_canary: bool
    requested_packet_blocks: tuple[str, ...]


def audit_dns(plan: PolicyPlan, *, listening: bool) -> DnsAudit:
    leak = plan.leak
    enabled = leak.dns_via_target and plan.dns_stub_port is not None
    interface = None
    if not enabled:
        problem = "No per-policy DNS stub configured"
    elif not listening:
        problem = "Per-policy DNS stub is not listening"
    elif plan.route != "dev" or not plan.interface:
        problem = "No active target interface"
    elif leak.dns_protocol == "doh" and find_spec("aiohttp") is None:
        problem = "DNS over HTTPS requires the snakevpn[doh] extra"
    else:
        try:
            upstream_endpoint(leak.dns_server, leak.dns_protocol)
        except ValueError:
            problem = "Invalid DNS upstream address"
        else:
            problem = None
            interface = plan.interface

    packet_blocks = (
        ("DoH", leak.block_doh),
        ("DoT", leak.block_dot),
        ("QUIC", leak.block_quic),
        ("IPv6", leak.ipv6 == "block"),
    )
    return DnsAudit(
        stub_listening=enabled and listening,
        upstream_interface=interface,
        upstream_problem=problem,
        firefox_canary=enabled and listening and leak.block_doh,
        requested_packet_blocks=tuple(name for name, requested in packet_blocks if requested),
    )
