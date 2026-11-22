"""CLI entry point for Stream A."""

from __future__ import annotations

import argparse
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from pyvpn import __version__
from pyvpn.apps.exclusions import config_exclusion_problems, exclusion_warnings
from pyvpn.apps.launcher import DaemonUnavailable as LauncherUnavailable
from pyvpn.apps.launcher import run as run_app
from pyvpn.apps.netns import NetworkNamespaceUnavailable
from pyvpn.cli.asn import add_asn_parser, add_cache_dir_argument, resolver_from_args, run_asn
from pyvpn.cli.install import (
    InstallError,
    InstallFile,
    desktop_file_path,
    render_desktop_file,
    render_systemd_unit,
    systemd_unit_path,
    write_install_file,
)
from pyvpn.cli.output import (
    format_apps,
    format_audit,
    format_mutation,
    format_status,
    print_json,
)
from pyvpn.config import (
    ConfigError,
    ConfigFileError,
    ConfigValidationError,
    load_config,
)
from pyvpn.constants import SOCKET_PATH
from pyvpn.daemon.client import (
    DaemonClient,
    DaemonClientError,
)
from pyvpn.rulefile.commands import (
    check,
    check_config,
    explain_config,
    explain_rules,
    export_policy,
    import_notes,
    import_rules,
)


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
    add_cache_dir_argument(test)

    commands.add_parser("reload", help="reload the daemon configuration")
    commands.add_parser("disable", help="remove pyvpn routing and rules")
    commands.add_parser("enable", help="reinstall pyvpn routing after disable")
    commands.add_parser("audit", help="describe routing and leak protection")

    run = commands.add_parser("run", help="place a launched process in a policy")
    run.add_argument("-p", "--policy", required=True, help="policy name or id")
    run.add_argument("--socket", default=argparse.SUPPRESS, help="daemon socket path")
    run.add_argument("--isolation", choices=("none", "netns"), default="none")
    run.add_argument("command_args", nargs=argparse.REMAINDER, help="command and arguments")

    install = commands.add_parser("install", help="render or write systemd installation files")
    install.add_argument("--scope", choices=("system", "user"), default="system")
    install.add_argument(
        "--exec-start",
        default=None,
        help="daemon executable (default: pyvpn-daemon on PATH, else /usr/bin/pyvpn-daemon)",
    )
    install.add_argument("--root", default=None, help="redirect absolute destinations for testing")
    install.add_argument("--write", action="store_true", help="write the generated unit file")

    desktop = commands.add_parser("desktop", help="render or write a desktop policy launcher")
    desktop.add_argument("--policy", required=True, help="policy name")
    desktop.add_argument("--scope", choices=("system", "user"), default="system")
    desktop.add_argument("--executable", default="/usr/bin/pyvpn")
    desktop.add_argument("--root", default=None, help="redirect absolute destinations for testing")
    desktop.add_argument("--write", action="store_true", help="write the generated desktop file")
    desktop.add_argument("--output", default=None, help="write to an explicit path")

    rules = commands.add_parser("rules", help="check or convert snake rule files")
    rules_commands = rules.add_subparsers(dest="rules_command", required=True)

    rules_check = rules_commands.add_parser("check", help="check a rule file")
    rules_check.add_argument("file", help="rule file")
    rules_check.add_argument("--convert", action="store_true", help="accept foreign list formats")
    add_cache_dir_argument(rules_check)

    rules_test = rules_commands.add_parser("test", help="test rule matching")
    rules_test.add_argument("source", help="rule file or config policy/name")
    rules_test.add_argument("names", nargs="*", help="DNS name chain")
    rules_test.add_argument("--config", default=None, help="configuration JSON path")

    rules_import = rules_commands.add_parser("import", help="convert a rule list")
    rules_import.add_argument("file", help="source rule file")

    rules_export = rules_commands.add_parser("export", help="export a config policy")
    rules_export.add_argument("policy", help="policy name")
    rules_export.add_argument("--config", default=None, help="configuration JSON path")

    add_asn_parser(commands)
    return parser


def _run_status(client: DaemonClient, as_json: bool) -> int:
    result = client.status()
    if as_json:
        print_json(result)
    else:
        print(format_status(result))
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


_SCHEMA_FAILED = ": configuration validation failed"


def _config_problems(exc: ConfigFileError | ConfigValidationError) -> list[str]:
    """one line per problem: ``source: error: location: message`` for schema errors."""
    if not isinstance(exc, ConfigValidationError) or not exc.problems:
        return [f"error: {exc}"]
    if exc.message.endswith(_SCHEMA_FAILED):
        source = exc.message.removesuffix(_SCHEMA_FAILED)
        return [f"{source}: error: {problem}" for problem in exc.problems]
    return [f"error: {exc.message} ({problem})" for problem in exc.problems]


def _run_test(args: argparse.Namespace, as_json: bool) -> int:
    try:
        config = load_config(args.config)
    except (ConfigFileError, ConfigValidationError) as exc:
        problems = _config_problems(exc)
        output = "\n".join([*problems, "errors found"]) + "\n"
        if as_json:
            print_json({"ok": False, "output": output, "errors": problems})
        else:
            sys.stdout.write(output)
        return 1
    result = check_config(config, resolver_from_args(args))
    output, code = result.output, result.code
    exclusion_errors = [
        problem.replace(": ", ": error: ", 1) for problem in config_exclusion_problems(config)
    ]
    warnings = [w.replace(": ", ": warning: ", 1) for w in exclusion_warnings(config)]
    if warnings:
        output = "\n".join(warnings) + "\n" + output
    if exclusion_errors:
        # The daemon refuses these configs (PLAN.md §3.3); say so here too.
        output = "\n".join(exclusion_errors) + "\n" + output.replace("ok\n", "errors found\n")
        code = 1
    if as_json:
        print_json({"ok": code == 0, "output": output})
    else:
        sys.stdout.write(output)
    return code


def _run_mutation(client: DaemonClient, as_json: bool, action: str) -> int:
    if action == "reload":
        result = client.reload()
    elif action == "enable":
        result = client.enable()
    else:
        result = client.disable()
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


def _run_app(args: argparse.Namespace) -> int:
    command = list(args.command_args)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        print("pyvpn: a command is required", file=sys.stderr)
        return 1
    policy: str | int = args.policy
    if args.policy.startswith("id:"):
        policy_text = args.policy[3:]
        if not policy_text.isascii() or not policy_text.isdigit():
            print("pyvpn: policy id must be a positive integer", file=sys.stderr)
            return 1
        policy = int(policy_text)
    elif args.policy.startswith("name:"):
        policy = args.policy[5:]
        if not policy:
            print("pyvpn: policy name must not be empty", file=sys.stderr)
            return 1
    elif args.policy.isascii() and args.policy.isdigit():
        policy = int(args.policy)
    try:
        run_app(
            policy,
            command,
            socket_path=args.socket if args.socket is not None else SOCKET_PATH,
            isolation=args.isolation,
        )
    except (
        DaemonClientError,
        LauncherUnavailable,
        NetworkNamespaceUnavailable,
        OSError,
        ValueError,
    ) as exc:
        print(f"pyvpn: {exc}", file=sys.stderr)
        return 1
    return 0


def _redirect_path(path: Path, root: str | None) -> Path:
    """redirect an absolute install path below a test root."""
    if root is None:
        return path
    return Path(root) / str(path).lstrip("/")


def _default_daemon_executable() -> str:
    """The installed ``pyvpn-daemon`` (pip puts it in a venv or /usr/local/bin)."""
    found = shutil.which("pyvpn-daemon")
    return str(Path(found).absolute()) if found else "/usr/bin/pyvpn-daemon"


def _run_install(args: argparse.Namespace, as_json: bool) -> int:
    unit = render_systemd_unit(args.exec_start or _default_daemon_executable())
    path = _redirect_path(systemd_unit_path(args.scope), args.root)
    if args.write:
        write_install_file(InstallFile(path, unit))

    result = {
        "written": bool(args.write),
        "path": str(path),
        "content": unit,
    }
    if as_json:
        print_json(result)
    else:
        print(f"systemd unit: {path}")
        if args.write:
            print("written")
        else:
            sys.stdout.write(unit)
    return 0


def _run_desktop(args: argparse.Namespace, as_json: bool) -> int:
    content = render_desktop_file(args.policy, args.executable)
    path = (
        Path(args.output)
        if args.output is not None
        else _redirect_path(desktop_file_path(args.policy, args.scope), args.root)
    )
    if args.write:
        write_install_file(InstallFile(path, content))

    result = {
        "written": bool(args.write),
        "path": str(path),
        "content": content,
    }
    if as_json:
        print_json(result)
    else:
        print(f"desktop entry: {path}")
        if args.write:
            print("written")
        else:
            sys.stdout.write(content)
    return 0


def _read_text_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc


def _run_rules(args: argparse.Namespace, as_json: bool) -> int:
    if args.rules_command == "check":
        text = _read_text_file(args.file)
        result = check(text, args.file, convert=args.convert, asn_prefixes=resolver_from_args(args))
        if as_json:
            print_json({"ok": result.code == 0, "output": result.output})
        else:
            sys.stdout.write(result.output)
        return result.code

    if args.rules_command == "test":
        if args.config:
            config = load_config(args.config)
            result = explain_config(config, [args.source, *args.names])
        else:
            text = _read_text_file(args.source)
            result = explain_rules(text.splitlines(), args.names)
        if as_json:
            print_json({"ok": result.code == 0, "output": result.output})
        else:
            sys.stdout.write(result.output)
        return result.code

    if args.rules_command == "import":
        text = _read_text_file(args.file)
        result, rule_file = import_rules(text, args.file)
        if as_json:
            print_json(
                {
                    "ok": result.code == 0,
                    "output": result.output,
                    "domains": list(rule_file.domains),
                    "asns": list(rule_file.asns),
                    "cidrs": list(rule_file.cidrs),
                }
            )
        else:
            sys.stdout.write(import_notes(text, args.file))
            sys.stdout.write(result.output)
        return result.code

    if args.rules_command == "export":
        config = load_config(args.config)
        policy = next((item for item in config.policies if item.name == args.policy), None)
        if policy is None:
            raise ConfigError(f"policy not found: {args.policy}")
        result = export_policy(policy)
        if as_json:
            print_json({"ok": result.code == 0, "output": result.output})
        else:
            sys.stdout.write(result.output)
        return result.code

    raise AssertionError("unhandled rules command")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "run":
            return _run_app(args)
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
        if args.command in {"reload", "disable", "enable"}:
            socket_path = args.socket if args.socket is not None else None
            client = DaemonClient(socket_path) if socket_path is not None else DaemonClient()
            return _run_mutation(client, args.json, args.command)
        if args.command == "audit":
            socket_path = args.socket if args.socket is not None else None
            client = DaemonClient(socket_path) if socket_path is not None else DaemonClient()
            return _run_audit(client, args.json)
        if args.command == "install":
            return _run_install(args, args.json)
        if args.command == "desktop":
            return _run_desktop(args, args.json)
        if args.command == "rules":
            return _run_rules(args, args.json)
        if args.command == "asn":
            return run_asn(args, args.json)
    except (ConfigError, DaemonClientError, InstallError) as exc:
        print(f"pyvpn: {exc}", file=sys.stderr)
        return 1
    raise AssertionError("unhandled CLI command")
