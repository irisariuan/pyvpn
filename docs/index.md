---
title: pyvpn wiki
description: Per-process policy routing for Linux. Send each app's traffic and DNS out through a chosen interface, with fallback or a kill switch.
canonical: https://irisariuan.github.io/pyvpn/
html: https://irisariuan.github.io/pyvpn/index.html
license: GPL-3.0-or-later
status: alpha (0.0.x)
---

# pyvpn wiki

**pyvpn is per-process policy routing for Linux.** It sends each app's
traffic, and its DNS, out through an interface you choose (`wg-jp`, `tun0`,
`wlan1`, …). When that interface is down, the policy falls back to the next
interface or the normal default route, or blocks the traffic (kill switch).

> **Status: alpha (0.0.x).** `pyvpn-daemon` routes traffic and enforces kill
> switches on Linux. It's tested end to end in network namespaces but hasn't
> been audited, so don't rely on it alone for privacy yet. A few configuration
> options are [not supported yet](usage.md#not-supported-yet).
>
> **Guides:** [Installation](install.md) · [Usage](usage.md)

- PyPI name: `snakevpn` · import package and command: `pyvpn`
- Python ≥ 3.11 · Linux with cgroup v2
- License: GNU GPL v3.0 or later
- Source: <https://github.com/irisariuan/pyvpn>

## Contents

1. [What pyvpn is (and is not)](#what-pyvpn-is-and-is-not)
2. [Concepts](#concepts)
3. [Install](#install)
4. [Configuration](#configuration)
5. [Commands](#commands)
6. [How it works](#how-it-works)
7. [DNS and leak protection](#dns-and-leak-protection)
8. [Limitations and risks](#limitations-and-risks)
9. [Roadmap](#roadmap)
10. [FAQ](#faq)
11. [Development](#development)
12. [License](#license)

## What pyvpn is (and is not)

pyvpn decides **which app leaves through which interface**. For example:

> Firefox and Steam leave through `wg-jp`, qBittorrent only through `tun0`
> with a kill switch, `ssh` to the office through `wlan1`, everything else
> through the normal default route.

pyvpn **does not create or manage VPN connections.** WireGuard, OpenVPN, a
provider's app, a second network card or a phone tether bring their
interfaces up themselves. pyvpn only routes apps through interfaces that
already exist.

It is the client-side counterpart of
[snake](https://github.com/irisariuan/snake), which picks a tunnel per
*device* on a router.

## Concepts

| Term | Meaning |
|---|---|
| **Target** | An existing network interface (`wg-jp`, `tun0`, `wlan1`) or a name pattern (`tun*`), plus an optional gateway. |
| **Policy** | A named rule: a set of apps, an ordered list of targets, and what to do when every target is down. |
| **App selector** | How a policy finds its apps: launched with `pyvpn run`, executable path or name, systemd unit, uid or user, Flatpak or Snap ID. |
| **`on_down`** | Used after every target in the list is down: `default` falls back to the normal route, `block` drops the traffic (kill switch). |
| **Usable target** | The link is up and has an address (and, with `"gateway": "auto"`, a gateway). Reachability probes are planned. |
| **Destination filter** | Optional domain, `asn:` or `cidr:` rules (snake's rule language) that limit a policy to matching destinations. |

### Target types

- **Point-to-point** (`tun0`, `wg0`, `ppp0`): routed with `default dev <iface>`.
- **Broadcast** (`eth1`, `wlan1`, `usb0`): needs a next hop, learned from the
  interface's own default route or DHCP lease, or set with `gateway`.
- **Patterns** (`tun*`, `wg-jp*`): for VPN apps whose interface name changes
  on each reconnect.

### App selectors

| Selector | Example | How it matches |
|---|---|---|
| launched by pyvpn | `pyvpn run -p JP -- firefox` | The child starts in cgroup `pyvpn.slice/p-<id>`; every descendant follows. |
| executable | `{"exe": "/usr/bin/qbittorrent"}`, `{"name": "steam"}` | A process watcher moves matching PIDs into the policy's cgroup. |
| systemd unit | `{"unit": "transmission-daemon.service"}` | The process watcher moves the unit's processes into the policy's cgroup. |
| user | `{"uid": 1001}`, `{"user": "torrent"}` | nft `meta skuid`. |
| Flatpak / Snap | `{"flatpak": "org.mozilla.firefox"}` | Its `app-flatpak-…scope` cgroup. |
| exclusions | `"exclude_apps": [...]` | Same selectors; an excluded app never matches. Not enforced yet. |

Sockets that are already open keep their route. New connections follow the
new policy.

## Install

```bash
pip install snakevpn
pyvpn --version
```

The PyPI package is `snakevpn`; the commands are `pyvpn` (CLI) and
`pyvpn-daemon` (root daemon). Requirements: Linux with cgroup v2 (the default
on current distributions), the `nft` command (nftables), and root for the
daemon. The CLI, including `pyvpn run`, runs as a normal user. The
[installation guide](install.md) covers systemd setup, upgrades and
uninstalling.

## Configuration

The configuration is JSON, in `/etc/pyvpn/config.json` by default. Targets
name interfaces; policies map apps to an ordered list of targets. The
[usage guide](usage.md#writing-a-configuration) explains every field.

```json
{
  "version": 1,
  "targets": [
    {"name": "jp",     "interface": "wg-jp"},
    {"name": "nl",     "interface": "tun*"},
    {"name": "office", "interface": "wlan1", "gateway": "auto"}
  ],
  "app_groups": [
    {"name": "browsers", "apps": [{"exe": "/usr/bin/firefox"}, {"flatpak": "com.google.Chrome"}]}
  ],
  "policies": [
    {"name": "Japan browsing", "targets": ["jp", "nl"], "on_down": "default",
     "apps": ["group:browsers", {"name": "steam"}],
     "leak": {"dns_via_target": true, "block_doh": true, "ipv6": "route"}},
    {"name": "Torrents", "targets": ["nl"], "on_down": "block",
     "apps": [{"exe": "/usr/bin/qbittorrent"}], "leak": {"ipv6": "block"}},
    {"name": "Office", "targets": ["office"],
     "apps": [{"name": "ssh"}], "domains": ["corp.example", "cidr:10.20.0.0/16"]}
  ]
}
```

### Main fields

| Field | Where | Values |
|---|---|---|
| `interface` | target | Interface name or pattern (`tun*`). |
| `gateway` | target | An address, or `"auto"` to require a discovered next hop. |
| `probe` | target | *Not supported yet:* a target with `true` stays unusable. |
| `targets` | policy | Target names in priority order. The first usable one wins. |
| `on_down` | policy | `default` or `block`. |
| `apps` | policy | App selectors or `group:<name>`. |
| `domains` | policy | Optional destination filters. |
| `isolation` | policy | *Not supported yet:* the daemon refuses `netns`. |
| `leak` | policy | DNS and leak toggles; see [DNS and leak protection](#dns-and-leak-protection). |

## Commands

```bash
pyvpn run -p "Japan browsing" -- firefox   # start an app inside a policy
pyvpn status                               # policies and their active routes
pyvpn apps                                 # policy bindings by cgroup and uid
pyvpn audit                                # what each policy does and does not protect
pyvpn reload                               # re-read the config (root)
pyvpn disable                              # remove all pyvpn rules and routes (root)
pyvpn test [config]                        # validate a config
pyvpn rules check example.rules            # validate destination rules (snake format)
pyvpn install --write                      # install the systemd unit for the daemon
pyvpn desktop --policy NAME                # print or install a menu launcher
```

`pyvpn rules` also has `test`, `import` and `export` subcommands. Put
`--json` before a command for machine-readable output. See the
[usage guide](usage.md) for examples and real output.

## How it works

```text
process ── in cgroup pyvpn.slice/p-<id>, or matched by uid / unit cgroup
   │
   ├─ DNS (port 53) ──► nft redirect ─► per-policy stub 127.0.0.1:53<id>
   │                                     resolves through the policy's interface
   │
   └─ packets ──► nft output chain: socket cgroupv2 match → fwmark
              ──► ip rule: fwmark → per-policy routing table
                    default dev <iface>     (active target)
                    unreachable             (kill switch)
              ──► nft postrouting: masquerade to the interface's address
```

- A small **root daemon** owns nftables, routes and cgroups. The CLI and
  `pyvpn run` run unprivileged and talk to it over a **unix socket**.
- Apps are identified by **cgroup v2** or by **uid**. An nft rule marks
  their packets with a **fwmark**; an **`ip rule`** sends that mark to the
  policy's routing table.
- A **netlink** watcher reacts as soon as an interface goes up or down, with
  no polling. When `tun0` disappears, the table switches to the next target,
  the default route, or `unreachable`.
- Each policy table also has a higher-metric `unreachable` route, so traffic
  stops rather than leaks if the device route vanishes before the daemon
  reacts.
- All Linux code sits behind the `Backend` protocol in
  `src/pyvpn/platform/base.py`, so other systems can be added later.

## DNS and leak protection

- Each policy gets its own DNS stub. nft redirects port 53 **from that
  policy's apps** to it, which also catches hard-coded resolvers such as
  `8.8.8.8`. The stub resolves through the policy's interface (plain, DoT or
  DoH) and returns SERVFAIL rather than falling back to another path.
- Other apps keep the system resolver. **pyvpn does not change system DNS.**
- Per-policy toggles: block DoT (port 853), block known DoH addresses, DoH
  canary domain, block QUIC, and IPv6 `route`, `block` or `off`.
- `pyvpn audit` lists what each policy does and does not protect.
- **Fail closed:** with `on_down: block`, traffic is dropped, never sent
  through the default route.
- `isolation: netns`, which runs an app in its own network namespace, is
  planned; the daemon refuses it for now.

## Limitations and risks

- **Linux only.** macOS, Windows and a proxy mode are deferred.
- **cgroup v2 is required.** There is no cgroup v1 or hybrid fallback yet.
- **Moving running processes** between cgroups can conflict with systemd
  scopes. Prefer `pyvpn run` or systemd units.
- **VPN apps with their own kill switch** can override pyvpn's rules. pyvpn
  drops marked traffic that would leave through the wrong interface, but
  `pyvpn audit` doesn't report competing rules yet.
- The daemon needs root; everything else runs as a normal user.

## Roadmap

| Milestone | Scope |
|---|---|
| M0 | Scaffold, CI, PyPI Trusted Publishing |
| M1 | Core app routing: daemon, cgroups, `pyvpn run`, nft marks, policy tables, kill switch |
| M2 | Targets: netlink watcher, interface patterns, gateways, ordered fallback, probes |
| M3 | App selectors (exe, name, unit, uid, Flatpak) and process watcher |
| M4 | Per-app DNS and leak protection, `pyvpn audit` |
| M5 | Destination filters (snake's rule language, ASN/CIDR) |
| M7 | netns isolation, `pyvpn install` (systemd), `--json`: **v0.1 release** |

## FAQ

**Does pyvpn connect to my VPN?**
No. Start the VPN with its own tool. pyvpn routes apps through the interface
the VPN creates.

**What happens when the VPN reconnects and the interface name changes?**
Use a pattern such as `tun*`. pyvpn sees the new interface through netlink
and re-installs the route.

**Does it change DNS for the whole system?**
No. Only apps in a policy use that policy's DNS stub.

**What if every target is down?**
With `on_down: default`, the app uses the normal route. With
`on_down: block`, its traffic is dropped.

**Why is the PyPI package called `snakevpn`?**
The name `pyvpn` was already taken on PyPI. The commands are still `pyvpn`
and `pyvpn-daemon`.

## Development

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check .
mypy src
pytest                         # unit tests: no root, never touch the host network
sudo pytest -m integration     # network-namespace tests (Linux, root)
```

Read before contributing:

- [PLAN.md](https://github.com/irisariuan/pyvpn/blob/main/PLAN.md): design, scope and milestones (source of truth)
- [WORKSTREAMS.md](https://github.com/irisariuan/pyvpn/blob/main/WORKSTREAMS.md): which workstream owns which directory
- [AGENTS.md](https://github.com/irisariuan/pyvpn/blob/main/AGENTS.md): working rules for people and coding agents

## License

pyvpn is free software under the
[GNU General Public License v3.0 or later](https://github.com/irisariuan/pyvpn/blob/main/LICENSE).
