"""Command options: ``CMD[SETTING=VALUE;SETTING=VALUE;...]:rule``.

Port of snake ``internal/match/options.go``::

    session[ttl=TIME;onlookup=0|1]:rule
    if:COND;then:route[ttl=TIME]:EXPR;else:drop[ttl=TIME]:EXPR

``ttl`` overrides the session TTL (seconds, or 90s, 10m, 1h). ``onlookup=1``
counts it from the lookup that started the session; ``onlookup=0``, the
default, from the last connection to the address.

``share=global|GROUP|DEVICE`` (repeatable) also routes the session for
others. A negative ttl (``ttl=-1``) never expires; such actions switch an
address on or off at each lookup by ``set=1`` (default), ``set=0`` or
``set=toggle``.

Options are separated by ``;`` or ``,``. TTLs are kept in seconds.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

FOREVER = -1.0
"""TTL of sessions that never expire (``ttl=-1``)."""

SET_ON = "1"
SET_OFF = "0"
SET_TOGGLE = "toggle"

SHARE_GLOBAL = "global"
"""Shares a session with every member of the policy."""

_MIN_TTL = 10.0
_MAX_TTL = 7 * 24 * 3600.0


class OptionError(ValueError):
    pass


@dataclass(frozen=True)
class Opts:
    ttl: float = 0.0  # seconds; 0: the global session TTL; <0: never expires
    onlookup: bool = False
    share: tuple[str, ...] = ()
    set: str = ""

    def permanent(self) -> bool:
        return self.ttl < 0

    def set_mode(self) -> str:
        """What a lookup does to a permanent session ("" for timed sessions)."""
        if not self.permanent():
            return ""
        return self.set or SET_ON

    def is_zero(self) -> bool:
        return self.ttl == 0 and not self.onlookup and not self.share and self.set == ""

    def __str__(self) -> str:
        parts: list[str] = []
        if self.ttl > 0:
            parts.append("ttl=" + format_ttl(self.ttl))
        if self.ttl < 0:
            parts.append("ttl=-1")
        if self.set not in ("", SET_ON):
            parts.append("set=" + self.set)
        if self.onlookup:
            parts.append("onlookup=1")
        parts.extend("share=" + sh for sh in self.share)
        return ";".join(parts)


def format_ttl(seconds: float) -> str:
    """Shortest whole unit (1h, 10m, 90s)."""
    s = round(seconds)
    if seconds == s and s % 3600 == 0:
        return f"{s // 3600}h"
    if seconds == s and s % 60 == 0:
        return f"{s // 60}m"
    return f"{s}s"


def split_cmd(s: str, cmd: str) -> tuple[str, bool, str, bool]:
    """Split ``cmd[opts]:rest`` or ``cmd:rest`` (cmd without case).

    Returns ``(opts, has_opts, rest, ok)``.
    """
    if len(s) <= len(cmd) or s[: len(cmd)].lower() != cmd:
        return "", False, "", False
    t = s[len(cmd) :]
    if t.startswith(":"):
        return "", False, t[1:], True
    if t.startswith("["):
        end = t.find("]:")
        if end < 0:
            return "", False, "", False
        return t[1:end], True, t[end + 2 :], True
    return "", False, "", False


def cmd_prefix(cmd: str, o: Opts) -> str:
    """``cmd:`` or ``cmd[opts]:``."""
    if o.is_zero():
        return cmd + ":"
    return f"{cmd}[{o}]:"


def parse_opts(text: str) -> Opts:
    ttl = 0.0
    onlookup = False
    share: list[str] = []
    set_ = ""
    for raw in re.split(r"[;,]", text):
        kv = raw.strip()
        if not kv:
            continue
        k, sep, v = kv.partition("=")
        k, v = k.strip().lower(), v.strip()
        if not sep:
            raise OptionError(f"option {kv!r} needs a value (name=value)")
        if k == "ttl":
            ttl = _parse_ttl(v)
        elif k == "onlookup":
            if v in ("1", "true", "yes", "on"):
                onlookup = True
            elif v in ("0", "false", "no", "off"):
                onlookup = False
            else:
                raise OptionError(f"onlookup must be 0 or 1, not {v!r}")
        elif k == "share":
            n = normalize_share(v)
            if n not in share:
                share.append(n)
        elif k == "set":
            lv = v.lower()
            if lv in ("1", "on", "true", "yes"):
                set_ = SET_ON
            elif lv in ("0", "off", "false", "no"):
                set_ = SET_OFF
            elif lv == "toggle":
                set_ = SET_TOGGLE
            else:
                raise OptionError(f"set must be 1, 0 or toggle, not {v!r}")
        else:
            raise OptionError(f"unknown option {k!r} (ttl, onlookup, share, set)")
    o = Opts(ttl=ttl, onlookup=onlookup, share=tuple(share), set=set_)
    if o.set and not o.permanent():
        raise OptionError("set= needs a negative ttl (ttl=-1): timed sessions end on their own")
    if o.permanent() and o.onlookup:
        raise OptionError("onlookup has no effect with a negative ttl (it never expires)")
    return o


_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "μs": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0}
_UNITS["h"] = 3600.0
_DUR_RE = re.compile(r"([0-9]*(?:\.[0-9]*)?)(ns|us|µs|μs|ms|s|m|h)")


def parse_duration(v: str) -> float:
    """Go's ``time.ParseDuration``, in seconds (raises ValueError)."""
    s = v
    neg = False
    if s[:1] in ("-", "+"):
        neg, s = s[0] == "-", s[1:]
    if s == "0":
        return 0.0
    if not s:
        raise ValueError(v)
    total = 0.0
    pos = 0
    while pos < len(s):
        m = _DUR_RE.match(s, pos)
        if not m or m.group(1) in ("", "."):
            raise ValueError(v)
        total += float(m.group(1)) * _UNITS[m.group(2)]
        pos = m.end()
    return -total if neg else total


def _parse_int(v: str) -> int | None:
    return int(v) if re.fullmatch(r"[+-]?[0-9]+", v) else None


def _parse_ttl(v: str) -> float:
    if v.startswith("-"):
        if _parse_int(v) is None:
            try:
                parse_duration(v)
            except ValueError:
                raise OptionError(
                    f"ttl {v!r}: seconds or a duration such as 90s, 10m, 1h; "
                    "negative: never expires"
                ) from None
        return FOREVER
    n = _parse_int(v)
    if n is not None:
        d = float(n)
    else:
        try:
            d = parse_duration(v)
        except ValueError:
            raise OptionError(f"ttl {v!r}: seconds or a duration such as 90s, 10m, 1h") from None
    if d < _MIN_TTL or d > _MAX_TTL:
        raise OptionError(f"ttl {v!r} must be between 10s and 7 days (or negative: never expires)")
    return d


_MAC_RES = (
    re.compile(r"([0-9a-fA-F]{2})[:]" * 5 + r"([0-9a-fA-F]{2})"),
    re.compile(r"([0-9a-fA-F]{2})[-]" * 5 + r"([0-9a-fA-F]{2})"),
    re.compile(r"([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})"),
)


def parse_mac(v: str) -> str | None:
    """A 6-byte MAC in canonical ``aa:bb:cc:dd:ee:ff`` form, or None."""
    for r in _MAC_RES:
        m = r.fullmatch(v)
        if m:
            hexs = "".join(m.groups()).lower()
            return ":".join(hexs[i : i + 2] for i in range(0, 12, 2))
    return None


def canonical_ip(v: str) -> str | None:
    """An IP address in canonical form (IPv4-mapped IPv6 as IPv4), or None."""
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id is not None:
            return None
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
    return str(ip)


def canonical_cidr(v: str) -> str | None:
    """A ``addr/len`` network with host bits cleared, or None."""
    addr, sep, plen = v.partition("/")
    if not sep or not re.fullmatch(r"[0-9]+", plen) or canonical_ip(addr) is None:
        return None
    try:
        return str(ipaddress.ip_network(f"{addr}/{plen}", strict=False))
    except ValueError:
        return None


_GROUP_RE = re.compile(r"[ _.\-+0-9a-zA-Z]+")


def normalize_share(v: str) -> str:
    """``global``, a device (IP, subnet, MAC; canonical) or a group name."""
    v = v.removeprefix("group:").strip()
    if not v:
        raise OptionError("share needs global, a device group or a device (IP, subnet, MAC)")
    if v.lower() == SHARE_GLOBAL:
        return SHARE_GLOBAL
    for f in (parse_mac, canonical_ip, canonical_cidr):
        c = f(v)
        if c is not None:
            return c
    if not _GROUP_RE.fullmatch(v):
        raise OptionError(f"share {v!r} is not global, a group name or a device (IP, subnet, MAC)")
    return v


def share_device(v: str) -> bool:
    """Whether a share= value names a device (not global or a group)."""
    return parse_mac(v) is not None or canonical_ip(v) is not None or canonical_cidr(v) is not None
