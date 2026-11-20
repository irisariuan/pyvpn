"""Target interface discovery and status watching."""

from pyvpn.targets.probes import parse_probe, probe_target, tcp_probe
from pyvpn.targets.resolver import resolve_interface, resolve_interfaces
from pyvpn.targets.watcher import InterfaceSnapshot, TargetWatcher, status_for_target

__all__ = [
    "InterfaceSnapshot",
    "TargetWatcher",
    "parse_probe",
    "probe_target",
    "resolve_interface",
    "resolve_interfaces",
    "status_for_target",
    "tcp_probe",
]
