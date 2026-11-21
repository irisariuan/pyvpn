"""Human-readable and JSON output helpers for the CLI."""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO


def print_json(value: Any, stream: TextIO | None = None) -> None:
    """write one compact JSON document."""
    if stream is None:
        stream = sys.stdout
    json.dump(value, stream, sort_keys=True)
    stream.write("\n")


def format_status(value: dict[str, Any]) -> str:
    """format a daemon status response."""
    enabled = "enabled" if value.get("enabled") else "disabled"
    lines = [f"daemon: {enabled}"]
    for policy in value.get("policies", []):
        if not isinstance(policy, dict):
            continue
        name = policy.get("name", "<unnamed>")
        route = policy.get("route", "main")
        interface = policy.get("interface") or "-"
        target = policy.get("target") or "-"
        lines.append(f"{policy.get('id', '-')}: {name}: {route} via {interface} ({target})")
    if value.get("last_error"):
        lines.append(f"last error: {value['last_error']}")
    return "\n".join(lines)


def format_apps(value: Any) -> str:
    """format an apps daemon response."""
    if not isinstance(value, list):
        return str(value)
    if not value:
        return "no active app bindings"

    lines = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        name = entry.get("policy", "<unnamed>")
        cgroups = ", ".join(entry.get("cgroup_paths", [])) or "-"
        uids = ", ".join(str(uid) for uid in entry.get("uids", [])) or "-"
        lines.append(f"{name}: cgroups={cgroups}; uids={uids}")
    return "\n".join(lines)


def format_mutation(value: Any, action: str) -> str:
    """format a reload or disable daemon result."""
    if isinstance(value, dict):
        message = value.get("message")
        if isinstance(message, str) and message:
            return message
    return f"{action}: ok"


def format_audit(value: Any) -> str:
    """format a daemon audit response."""
    if not isinstance(value, dict):
        return str(value)

    lines = []
    if "enabled" in value:
        lines.append(f"enabled: {'yes' if value['enabled'] else 'no'}")
    if "policies" in value:
        lines.append(f"policies: {len(value['policies'])}")
    for key, result in value.items():
        if key not in {"enabled", "policies"}:
            if isinstance(result, (dict, list)):
                continue
            lines.append(f"{key}: {result}")
    return "\n".join(lines) if lines else "audit: ok"
