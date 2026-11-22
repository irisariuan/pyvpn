"""``pyvpn asn status|refresh``: the on-disk ASN prefix cache (PLAN.md §3.4).

``refresh`` downloads prefixes from RIPEstat and writes the cache. It changes
no routing and needs no privileges beyond write access to the cache
directory; with the default directory (``/var/lib/pyvpn/asn``, which the
daemon reads) that means ``sudo pyvpn asn refresh``. The daemon only reads the
cache, on start and reload.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from pyvpn.cli.output import print_json
from pyvpn.config import ConfigError, load_config
from pyvpn.constants import STATE_DIR
from pyvpn.match.asn import AsnCache
from pyvpn.match.pattern import RuleError, parse_asn
from pyvpn.match.policy import AsnResolver
from pyvpn.rulefile.commands import CommandResult, asn_refresh, asn_status, config_asns

DEFAULT_CACHE_DIR = Path(STATE_DIR) / "asn"


def add_cache_dir_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--asn-cache",
        default=None,
        help=f"ASN prefix cache directory (default {DEFAULT_CACHE_DIR})",
    )


def cache_from_args(args: argparse.Namespace) -> AsnCache:
    """The cache the CLI reads. Like the daemon, it does not trust files that
    another user could have written (owner must be root or the caller)."""
    directory = getattr(args, "asn_cache", None) or DEFAULT_CACHE_DIR
    return AsnCache(directory, trusted_uids={0, os.geteuid()})


def resolver_from_args(args: argparse.Namespace) -> AsnResolver:
    return cache_from_args(args).usable


def add_asn_parser(commands: Any) -> None:
    asn = commands.add_parser("asn", help="show or refresh the ASN prefix cache")
    sub = asn.add_subparsers(dest="asn_command", required=True)
    for name, help_text in (
        ("status", "show cached prefixes for the config's asn: rules"),
        ("refresh", "download prefixes for the config's asn: rules (RIPEstat)"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("asns", nargs="*", help="ASNs (default: those in the config)")
        p.add_argument("--config", default=None, help="configuration JSON path")
        add_cache_dir_argument(p)
        if name == "refresh":
            p.add_argument("--force", action="store_true", help="refetch fresh entries too")


def _asns(args: argparse.Namespace) -> list[int]:
    if args.asns:
        try:
            return [parse_asn(a) for a in args.asns]
        except RuleError as e:
            raise ConfigError(str(e)) from None
    return config_asns(load_config(args.config))


def run_asn(args: argparse.Namespace, as_json: bool) -> int:
    cache = cache_from_args(args)
    asns = _asns(args)
    result: CommandResult
    if args.asn_command == "status":
        result = asn_status(cache, asns)
        extra: dict[str, Any] = {
            "entries": [
                {
                    "asn": e.asn,
                    "state": e.state,
                    "fetched": e.fetched,
                    "prefixes": len(e.prefixes),
                    "error": e.error,
                }
                for e in (cache.entry(a) for a in asns)
            ]
        }
    elif args.asn_command == "refresh":
        result = asn_refresh(cache, asns, force=args.force)
        extra = {}
    else:
        raise AssertionError("unhandled asn command")
    if as_json:
        print_json({"ok": result.code == 0, "output": result.output, **extra})
    else:
        sys.stdout.write(result.output)
    return result.code
