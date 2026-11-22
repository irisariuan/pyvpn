"""Render the nft JSON built by ``ruleset`` as nft script text.

nft 1.0.9 (Ubuntu 24.04, Debian 12 backports) cannot parse ``socket cgroupv2``
in JSON, so the backend loads the same commands as text with ``nft -f -``.
Both forms run as one transaction. Only the subset of nft JSON the builder
emits is supported; anything else raises ``ValueError`` instead of being
guessed.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from pyvpn.netfilter.ruleset import Json

# Left-hand sides whose string values are user data and must be quoted.
_QUOTED_KEYS = {"oifname", "iifname", "cgroupv2"}


def render(doc: Json) -> str:
    return "".join(_command(cmd) + "\n" for cmd in doc["nftables"])


def _command(cmd: Json) -> str:
    ((verb, body),) = cmd.items()
    ((kind, obj),) = body.items()
    if verb not in ("add", "delete"):
        raise ValueError(f"unsupported nft verb {verb!r}")
    if kind == "table":
        return f"{verb} table {obj['family']} {obj['name']}"
    where = f"{obj['family']} {obj['table']}"
    if kind == "set" and verb == "add":
        flags = ", ".join(obj.get("flags", ()))
        parts = [f"type {obj['type']};"]
        if flags:
            parts.append(f"flags {flags};")
        if obj.get("auto-merge"):
            parts.append("auto-merge;")
        if obj.get("elem"):
            parts.append(f"elements = {{ {_elements(obj['elem'])} }};")
        return f"add set {where} {obj['name']} {{ {' '.join(parts)} }}"
    if kind == "chain" and verb == "add":
        if "hook" not in obj:
            return f"add chain {where} {obj['name']}"
        spec = (
            f"type {obj['type']} hook {obj['hook']} priority {obj['prio']}; policy {obj['policy']};"
        )
        return f"add chain {where} {obj['name']} {{ {spec} }}"
    if kind == "rule" and verb == "add":
        exprs = " ".join(_statement(e) for e in obj["expr"])
        return f"add rule {where} {obj['chain']} {exprs}"
    if kind == "element" and verb == "add":
        return f"add element {where} {obj['name']} {{ {_elements(obj['elem'])} }}"
    raise ValueError(f"unsupported nft command {verb} {kind}")


def _elements(elems: list[Any]) -> str:
    out = []
    for e in elems:
        if isinstance(e, dict):
            out.append(f"{e['prefix']['addr']}/{e['prefix']['len']}")
        else:
            out.append(str(e))
    return ", ".join(out)


def _statement(e: Json) -> str:
    ((kind, v),) = e.items()
    if kind == "match":
        left, quoted = _expr(v["left"])
        op = "" if v["op"] == "==" else f"{v['op']} "
        right = _value(v["right"], quoted)
        if left in ("meta oifname", "meta iifname"):
            # Target discovery supplies an actual name. nft interprets an
            # unescaped trailing asterisk as a prefix match.
            right = right.replace("*", r"\*")
        return f"{left} {op}{right}"
    if kind == "mangle":
        return f"{_expr(v['key'])[0]} set {_expr(v['value'])[0]}"
    if kind in ("accept", "drop", "return"):
        return kind
    if kind in ("jump", "goto"):
        return f"{kind} {v['target']}"
    if kind == "reject":
        return f"reject with {v['type']} type {v['expr']}" if v else "reject"
    if kind == "redirect":
        return f"redirect to :{int(v['port'])}"
    if kind == "masquerade":
        return "masquerade"
    raise ValueError(f"unsupported nft statement {kind!r}")


def _expr(e: Any) -> tuple[str, bool]:
    """Render an expression; also report whether string operands need quotes."""
    if isinstance(e, int):
        return f"{e:#x}", False
    ((kind, v),) = e.items()
    if kind == "meta":
        return f"meta {v['key']}", v["key"] in _QUOTED_KEYS
    if kind == "ct":
        return f"ct {v['key']}", False
    if kind == "payload":
        return f"{v['protocol']} {v['field']}", False
    if kind == "socket":
        level = f" level {int(v['level'])}" if "level" in v else ""
        return f"socket {v['key']}{level}", v["key"] in _QUOTED_KEYS
    if kind in ("&", "|"):
        a, b = v
        return f"{_expr(a)[0]} {kind} {_expr(b)[0]}", False
    raise ValueError(f"unsupported nft expression {kind!r}")


def _value(v: Any, quoted: bool) -> str:
    if isinstance(v, bool):
        raise ValueError("unsupported boolean nft value")
    if isinstance(v, int):
        return f"{v:#x}" if v > 0xFFFF else str(v)
    if isinstance(v, str):
        if quoted:
            if any(c in v for c in '"\\;') or not v.isprintable():
                raise ValueError(f"refusing to quote unsafe nft string {v!r}")
            return f'"{v}"'
        if not v.replace("@", "", 1).replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"refusing to render bare nft symbol {v!r}")
        return v
    if isinstance(v, dict) and "set" in v:
        return "{ " + ", ".join(_value(x, quoted) for x in v["set"]) + " }"
    if isinstance(v, dict) and "prefix" in v:
        prefix = v["prefix"]
        addr = ip_address(prefix["addr"])  # refuses anything but an address
        return f"{addr}/{int(prefix['len'])}"
    raise ValueError(f"unsupported nft value {v!r}")
