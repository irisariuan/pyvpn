"""Addresses of well-known public DoH resolvers, blocked on 443 by ``block_doh``.

Apps that speak DoH to these bypass the policy's DNS stub, so a policy with
destination rules would never learn their answers and Firefox / Chrome would
resolve outside the target. The list only needs the big anycast resolvers that
browsers ship as presets; the stub also answers Firefox's canary domain.
"""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network

DOH_V4: tuple[IPv4Network, ...] = tuple(
    IPv4Network(a)
    for a in (
        "1.0.0.1/32",  # Cloudflare
        "1.0.0.2/32",
        "1.0.0.3/32",
        "1.1.1.1/32",
        "1.1.1.2/32",
        "1.1.1.3/32",
        "8.8.4.4/32",  # Google
        "8.8.8.8/32",
        "9.9.9.9/32",  # Quad9
        "9.9.9.10/32",
        "9.9.9.11/32",
        "45.90.28.0/24",  # NextDNS anycast
        "45.90.30.0/24",
        "94.140.14.14/32",  # AdGuard
        "94.140.15.15/32",
        "149.112.112.10/32",
        "149.112.112.11/32",
        "149.112.112.112/32",
        "208.67.220.220/32",  # OpenDNS
        "208.67.222.222/32",
    )
)

DOH_V6: tuple[IPv6Network, ...] = tuple(
    IPv6Network(a)
    for a in (
        "2001:4860:4860::8844/128",
        "2001:4860:4860::8888/128",
        "2606:4700:4700::1001/128",
        "2606:4700:4700::1111/128",
        "2620:119:35::35/128",
        "2620:119:53::53/128",
        "2620:fe::9/128",
        "2620:fe::fe/128",
        "2a10:50c0::ad1:ff/128",
        "2a10:50c0::ad2:ff/128",
    )
)
