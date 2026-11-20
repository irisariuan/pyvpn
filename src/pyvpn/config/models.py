"""Config models for PLAN.md §5 (Phase 0 contract: fields only).

Stream A owns full validation and migrations; only what other streams rely on
is checked here.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pyvpn.constants import MAX_POLICIES


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Target(_Model):
    name: str
    interface: str  # exact name or glob pattern ("tun*")
    gateway: Literal["auto"] | IPv4Address | IPv6Address | None = None
    probe: bool = False


class AppSelector(_Model):
    """One way of identifying an app; exactly one field is set."""

    exe: str | None = None
    name: str | None = None
    unit: str | None = None
    uid: int | None = None
    user: str | None = None
    flatpak: str | None = None
    snap: str | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> AppSelector:
        if sum(v is not None for v in self.model_dump().values()) != 1:
            raise ValueError("an app selector needs exactly one field")
        return self


AppRef = AppSelector | str  # str: "group:<name>"


class AppGroup(_Model):
    name: str
    apps: tuple[AppSelector, ...]


class LeakSettings(_Model):
    dns_via_target: bool = True
    dns_server: str | None = None
    dns_protocol: Literal["plain", "dot", "doh"] = "plain"
    block_doh: bool = False
    block_dot: bool = False
    block_quic: bool = False
    ipv6: Literal["route", "block", "off"] = "route"


class Policy(_Model):
    name: str
    targets: tuple[str, ...]  # target names, priority order (on_down "next" is implied)
    on_down: Literal["default", "block"] = "default"
    apps: tuple[AppRef, ...] = ()
    exclude_apps: tuple[AppRef, ...] = ()
    domains: tuple[str, ...] = ()  # snake rule-language destination filters
    isolation: Literal["none", "netns"] = "none"
    leak: LeakSettings = Field(default_factory=LeakSettings)

    @model_validator(mode="after")
    def _has_scope(self) -> Policy:
        if not self.apps and not self.domains:
            raise ValueError(f"policy {self.name!r} needs apps, domains or both")
        return self


class Settings(_Model):
    probe_targets: tuple[str, ...] = ("1.1.1.1:443",)
    probe_interval: float = 15.0


class Config(_Model):
    version: Literal[1] = 1
    targets: tuple[Target, ...] = ()
    app_groups: tuple[AppGroup, ...] = ()
    policies: tuple[Policy, ...] = ()
    settings: Settings = Field(default_factory=Settings)

    @model_validator(mode="after")
    def _refs(self) -> Config:
        if len(self.policies) > MAX_POLICIES:
            raise ValueError(f"at most {MAX_POLICIES} policies")
        names = {t.name for t in self.targets}
        for p in self.policies:
            missing = [t for t in p.targets if t not in names]
            if missing:
                raise ValueError(f"policy {p.name!r}: unknown targets {missing}")
        return self

    def policy_id(self, name: str) -> int:
        """1-based policy id, in config order."""
        for i, p in enumerate(self.policies, start=1):
            if p.name == name:
                return i
        raise KeyError(name)
