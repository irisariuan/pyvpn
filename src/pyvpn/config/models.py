"""Config models for PLAN.md §5 (Phase 0 contract: fields only).

Stream A owns full validation and migrations; only what other streams rely on
is checked here.
"""

from __future__ import annotations

import ipaddress
import math
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from pyvpn.constants import MAX_POLICIES


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Target(_Model):
    name: str
    interface: str  # exact name or glob pattern ("tun*")
    gateway: Literal["auto"] | IPv4Address | IPv6Address | None = None
    probe: StrictBool = False

    @model_validator(mode="after")
    def _names(self) -> Target:
        if not self.name.strip():
            raise ValueError("target name must not be empty")
        if not self.interface.strip():
            raise ValueError("target interface must not be empty")
        return self


class AppSelector(_Model):
    """One way of identifying an app; exactly one field is set."""

    exe: str | None = None
    name: str | None = None
    unit: str | None = None
    uid: int | None = None
    user: str | None = None
    flatpak: str | None = None
    snap: str | None = None

    @field_validator("uid", mode="before")
    @classmethod
    def _uid_type(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("uid must be an integer")
        return value

    @model_validator(mode="after")
    def _valid_selector(self) -> AppSelector:
        for field in ("exe", "name", "unit", "user", "flatpak", "snap"):
            value = getattr(self, field)
            if value is not None and not value.strip():
                raise ValueError(f"{field} selector must not be empty")
        if self.uid is not None and not 0 <= self.uid <= 4294967294:
            raise ValueError("uid must be between 0 and 4294967294")
        return self

    @model_validator(mode="after")
    def _exactly_one(self) -> AppSelector:
        if sum(v is not None for v in self.model_dump().values()) != 1:
            raise ValueError("an app selector needs exactly one field")
        return self


AppRef = AppSelector | str  # str: "group:<name>"


class AppGroup(_Model):
    name: str
    apps: tuple[AppSelector, ...]

    @model_validator(mode="after")
    def _valid_group(self) -> AppGroup:
        if not self.name.strip():
            raise ValueError("app group name must not be empty")
        if not self.apps:
            raise ValueError(f"app group {self.name!r} needs at least one app")
        return self


class LeakSettings(_Model):
    dns_via_target: StrictBool = True
    dns_server: str | None = None
    dns_protocol: Literal["plain", "dot", "doh"] = "plain"
    block_doh: StrictBool = False
    block_dot: StrictBool = False
    block_quic: StrictBool = False
    ipv6: Literal["route", "block", "off"] = "route"

    @model_validator(mode="after")
    def _dns_server(self) -> LeakSettings:
        if self.dns_server is None:
            return self
        value = self.dns_server.strip()
        if not value:
            raise ValueError("dns_server must not be empty")
        name = None
        address_text = value
        if "@" in value:
            name, address_text = value.split("@", 1)
            if not name or "@" in address_text:
                raise ValueError("dns_server must use tls-name@address")
            if not name.isascii() or any(
                not (character.isalnum() or character in ".-") for character in name
            ):
                raise ValueError("dns_server TLS name must be a valid DNS hostname")
        if "%" in address_text:
            raise ValueError("dns_server must use an unscoped IP address")
        if "@" in value and self.dns_protocol == "plain":
            raise ValueError("plain dns_server must not include a TLS name")
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as exc:
            raise ValueError("dns_server must be an IP address or tls-name@IP") from exc
        if (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or str(address) == "255.255.255.255"
        ):
            raise ValueError("dns_server must be a remote unicast IP address")
        return self


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
        if not self.name.strip():
            raise ValueError("policy name must not be empty")
        if not self.targets:
            raise ValueError(f"policy {self.name!r} needs at least one target")
        return self


class Settings(_Model):
    probe_targets: tuple[str, ...] = ("1.1.1.1:443",)
    probe_interval: float = 15.0

    @field_validator("probe_interval", mode="before")
    @classmethod
    def _probe_interval_type(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("probe_interval must be a number")
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError as exc:
                raise ValueError("probe_interval must be a number") from exc
        if not isinstance(value, (int, float)):
            raise ValueError("probe_interval must be a number")
        return value

    @model_validator(mode="after")
    def _interval(self) -> Settings:
        if not math.isfinite(self.probe_interval) or self.probe_interval <= 0:
            raise ValueError("probe_interval must be a finite value greater than zero")
        for target in self.probe_targets:
            host, separator, port_text = target.rpartition(":")
            if not separator or not host or not port_text:
                raise ValueError(f"invalid probe target: {target!r}")
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            try:
                ipaddress.ip_address(host)
            except ValueError as exc:
                raise ValueError("probe targets must use IP literals") from exc
            if not port_text.isascii() or not port_text.isdigit():
                raise ValueError(f"invalid probe port: {port_text}")
            port = int(port_text)
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid probe port: {port}")
        return self


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
        target_names = [target.name for target in self.targets]
        if len(target_names) != len(set(target_names)):
            raise ValueError("target names must be unique")
        policy_names = [policy.name for policy in self.policies]
        if len(policy_names) != len(set(policy_names)):
            raise ValueError("policy names must be unique")
        group_names = [group.name for group in self.app_groups]
        if len(group_names) != len(set(group_names)):
            raise ValueError("app group names must be unique")
        names = {t.name for t in self.targets}
        groups = set(group_names)
        for p in self.policies:
            missing = [t for t in p.targets if t not in names]
            if missing:
                raise ValueError(f"policy {p.name!r}: unknown targets {missing}")
            for app_ref in (*p.apps, *p.exclude_apps):
                if isinstance(app_ref, str):
                    prefix = "group:"
                    if not app_ref.startswith(prefix):
                        raise ValueError(
                            f"policy {p.name!r}: app reference {app_ref!r} must use group:<name>"
                        )
                    group_name = app_ref[len(prefix) :]
                    if not group_name or group_name not in groups:
                        raise ValueError(f"policy {p.name!r}: unknown app group {group_name!r}")
        return self

    def policy_id(self, name: str) -> int:
        """1-based policy id, in config order."""
        for i, p in enumerate(self.policies, start=1):
            if p.name == name:
                return i
        raise KeyError(name)
