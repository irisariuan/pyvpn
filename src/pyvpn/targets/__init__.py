"""Target interface discovery and status watching."""

from pyvpn.targets.probes import Connector, parse_probe, probe_target
from pyvpn.targets.resolver import resolve_interface, resolve_interfaces
from pyvpn.targets.watcher import InterfaceSnapshot, SnapshotTargetWatcher, status_for_target

__all__ = [
    "Connector",
    "InterfaceSnapshot",
    "SnapshotTargetWatcher",
    "parse_probe",
    "probe_target",
    "resolve_interface",
    "resolve_interfaces",
    "status_for_target",
]
