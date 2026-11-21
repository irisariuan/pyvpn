"""CLI entry point for Stream A."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from pyvpn import __version__
from pyvpn.cli.output import (
    format_apps,
    format_audit,
    format_mutation,
    format_status,
    print_json,
)
from pyvpn.config import (
    ConfigError,
    load_config,
)
from pyvpn.daemon.client import (
    DaemonClient,
    DaemonClientError,
)
from pyvpn.rulefile.commands import check_config


def build_parser() -> argparse.ArgumentParser:
    """build the public pyvpn argument parser."""
    parser = argparse.ArgumentParser(prog="pyvpn", description="Per-process policy routing")
    parser.add_argument("--version", action="version", version=f"pyvpn {__version__}")
    parser.add_argument("--json", action="store_true", help="write machine-readable JSON")
    parser.add_argument(
        "--socket",
        default=None,
        help="daemon socket path for status and app queries",
    )

    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="show daemon and policy status")
    commands.add_parser("apps", help="show live app bindings")

    policy = commands.add_parser("policy", help="show configured policies")
    policy.add_argument("name", nargs="?", help="policy name")
    policy.add_argument("--config", default=None, help="configuration JSON path")

    test = commands.add_parser("test", help="validate configuration and policy rules")
    test.add_argument("config", nargs="?", default=None, help="configuration JSON path")

    commands.add_parser("reload", help="reload the daemon configuration")
    commands.add_parser("disable", help="remove pyvpn routing and rules")
    commands.add_parser("audit", help="describe routing and leak protection")
    return parser


def _run_status(client: DaemonClient, as_json: bool) -> int:
    result = client.status()
    if as_json:
        print_json(result)
    else:
        print(format_status(result if isinstance(result, dict) else {}))
    return 0


def _run_apps(client: DaemonClient, as_json: bool) -> int:
    result = client.apps()
    if as_json:
        print_json(result)
    else:
        print(format_apps(result))
    return 0


def _run_policy(args: argparse.Namespace, as_json: bool) -> int:
    config = load_config(args.config)
    selected = [
        policy for policy in config.policies if args.name is None or policy.name == args.name
    ]
    if args.name is not None and not selected:
        raise ConfigError(f"policy not found: {args.name}")

    if as_json:
        print_json(
            {
                "policies": [
                    {
                        "name": policy.name,
                        "targets": list(policy.targets),
                        "on_down": policy.on_down,
                        "apps": [
                            app.model_dump(exclude_none=True) if hasattr(app, "model_dump") else app
                            for app in policy.apps
                        ],
                        "exclude_apps": [
                            app.model_dump(exclude_none=True) if hasattr(app, "model_dump") else app
                            for app in policy.exclude_apps
                        ],
                        "domains": list(policy.domains),
                        "isolation": policy.isolation,
                        "leak": policy.leak.model_dump(),
                    }
                    for policy in selected
                ]
            }
        )
        return 0

    for policy in selected:
        print(policy.name)
        print(f"  targets: {', '.join(policy.targets)}")
        print(f"  on_down: {policy.on_down}")
        print(f"  isolation: {policy.isolation}")
        print(f"  domains: {', '.join(policy.domains) or '-'}")
        print(f"  apps: {len(policy.apps)}")
        print(f"  excluded apps: {len(policy.exclude_apps)}")
    return 0


def _run_test(args: argparse.Namespace, as_json: bool) -> int:
    config = load_config(args.config)
    result = check_config(config)
    if as_json:
        print_json({"ok": result.code == 0, "output": result.output})
    else:
        sys.stdout.write(result.output)
    return result.code


def _run_mutation(client: DaemonClient, as_json: bool, action: str) -> int:
    result = client.reload() if action == "reload" else client.disable()
    if as_json:
        print_json(result)
    else:
        print(format_mutation(result, action))
    return 0


def _run_audit(client: DaemonClient, as_json: bool) -> int:
    result = client.audit()
    if as_json:
        print_json(result)
    else:
        print(format_audit(result))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command in {"status", "apps"}:
            socket_path = args.socket if args.socket is not None else None
            client = DaemonClient(socket_path) if socket_path is not None else DaemonClient()
            if args.command == "status":
                return _run_status(client, args.json)
            return _run_apps(client, args.json)
        if args.command == "policy":
            return _run_policy(args, args.json)
        if args.command == "test":
            return _run_test(args, args.json)
        if args.command in {"reload", "disable"}:
            socket_path = args.socket if args.socket is not None else None
            client = DaemonClient(socket_path) if socket_path is not None else DaemonClient()
            return _run_mutation(client, args.json, args.command)
        if args.command == "audit":
            socket_path = args.socket if args.socket is not None else None
            client = DaemonClient(socket_path) if socket_path is not None else DaemonClient()
            return _run_audit(client, args.json)
    except (ConfigError, DaemonClientError) as exc:
        print(f"pyvpn: {exc}", file=sys.stderr)
        return 1
    raise AssertionError("unhandled CLI command")
