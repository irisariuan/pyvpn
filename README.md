# pyvpn

**Per-process policy routing for Linux.** pyvpn sends each app's traffic, and
its DNS, out through an interface you choose (`wg-jp`, `tun0`, `wlan1`, …).
When that interface is down, the policy falls back to the next interface or
the normal default route, or blocks the traffic (kill switch).

> Firefox and Steam leave through `wg-jp`, qBittorrent only through `tun0`
> with a kill switch, `ssh` to the office through `wlan1`, everything else
> through the normal default route.

pyvpn **does not create or manage VPN connections.** WireGuard, OpenVPN, a
provider's app, a second NIC or a phone tether bring their interfaces up
themselves; pyvpn only decides which app leaves through which of them. It is
the client-side counterpart of [snake](https://github.com/irisariuan/snake),
which picks a tunnel per *device* on a router.

## Status

Early development. Nothing described below as a command works yet; the CLI
currently only prints its version. Work follows the milestones in
[PLAN.md §7](PLAN.md#7-milestones):

| | Milestone |
|---|---|
| M0 | Scaffold, CI, PyPI Trusted Publishing |
| M1 | Core app routing: daemon, cgroups, `pyvpn run`, nft marks, policy tables, kill switch |
| M2 | Targets: netlink watcher, interface patterns, gateways, ordered fallback, probes |
| M3 | App selectors (exe, name, unit, uid, Flatpak) and process watcher |
| M4 | Per-app DNS and leak protection, `pyvpn audit` |
| M5 | Destination filters (snake's rule language, ASN/CIDR) |
| M7 | netns isolation, `pyvpn install` (systemd), `--json`: **v0.1 release** |

**Linux only** (cgroup v2 required). macOS, Windows and proxy mode (M6, M8,
M9) are deferred.

## Install

Not released yet. It will be published on PyPI as **`snakevpn`** (`pyvpn` is
taken there); the import package and command are `pyvpn`. Python ≥ 3.11.

```bash
pip install snakevpn   # planned
pyvpn --version
```

## Configuration (planned)

Targets are interfaces (or patterns); policies map apps to an ordered list of
targets. From [PLAN.md §5](PLAN.md#5-configuration-sketch), shortened:

```json
{
  "version": 1,
  "targets": [
    {"name": "jp", "interface": "wg-jp"},
    {"name": "nl", "interface": "tun*", "probe": true}
  ],
  "policies": [
    {"name": "Japan browsing", "targets": ["jp", "nl"], "on_down": "default",
     "apps": [{"exe": "/usr/bin/firefox"}, {"name": "steam"}],
     "leak": {"dns_via_target": true, "block_doh": true, "ipv6": "route"}},
    {"name": "Torrents", "targets": ["nl"], "on_down": "block",
     "apps": [{"exe": "/usr/bin/qbittorrent"}], "leak": {"ipv6": "block"}}
  ]
}
```

`on_down` is `default` (fall back to the normal route) or `block` (kill
switch), tried after every target in the list is down.

## Commands (planned)

```bash
pyvpn run -p "Japan browsing" -- firefox   # start an app inside a policy
pyvpn status                               # policies, active targets
pyvpn apps                                 # live PID → policy → interface
pyvpn audit                                # what each policy does and does not protect
pyvpn rules check|test|import|export       # destination rules (snake format)
pyvpn install                              # systemd unit for the daemon
pyvpn disable                              # remove all pyvpn rules and routes
```

## How it works

- A small **root daemon** owns nft, routes and cgroups. The CLI and
  `pyvpn run` run unprivileged and talk to it over a **unix socket**; `run`
  asks the daemon to put its own PID in the policy's cgroup, then `exec`s
  the command.
- Apps are identified by cgroup v2 (`pyvpn.slice/p-<id>`, systemd units,
  Flatpak scopes) or by uid. An nft `output` chain matches them with
  `socket cgroupv2` and sets a **fwmark**; an **`ip rule`** sends that mark
  to a per-policy routing table (`default dev <iface>`, or `unreachable` for
  the kill switch). Marked traffic is masqueraded to the interface's address.
- A **netlink** watcher reconciles as soon as an interface goes up or down,
  with no polling.
- Each policy gets its own DNS stub; port 53 from that policy's apps is
  redirected to it and resolved through the policy's interface. System DNS
  is left alone.

All Linux-specific code sits behind the `Backend` protocol in
`src/pyvpn/platform/base.py` (using `pyroute2`), so other OSes can be added
later. Details: [PLAN.md §3](PLAN.md#3-how-it-works).

## Development

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check .
mypy src
pytest                         # unit tests, no root, never touch the host network
sudo pytest -m integration     # network-namespace integration tests (Linux, root)
```

Before contributing, read:

- [PLAN.md](PLAN.md): design, scope and milestones (source of truth)
- [WORKSTREAMS.md](WORKSTREAMS.md): which workstream owns which directory,
  and the shared Phase 0 contracts
- [AGENTS.md](AGENTS.md): working rules (fail closed, test rules, commits,
  branch names)

## License

MIT
