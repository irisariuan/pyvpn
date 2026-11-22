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

**Alpha (0.0.x): pyvpn does not route traffic yet.** The CLI, configuration
validation and rule tools work, and the `pyvpn-daemon` daemon ships. The
Linux backend that applies the nft rules and routes is not in this release
yet, so the daemon refuses to start unless you pass `--backend dry-run`.
That mode exercises the daemon, CLI and DNS stubs, but it **applies no
routing and no leak protection** (see
[PLAN.md §7](https://github.com/irisariuan/pyvpn/blob/main/PLAN.md#7-milestones)
for milestones). Do not rely on it for privacy yet.

**Linux only**, and it needs cgroup v2. macOS and Windows are not supported.

## Install

```bash
pip install snakevpn
pyvpn --version
```

The PyPI package is **`snakevpn`**; the command and the Python import are
`pyvpn`. Requires Python 3.11 or newer.

Optional extras:

- `snakevpn[doh]`: DNS over HTTPS upstreams (`dns_protocol: "doh"`).
- `snakevpn[re2]`: needed before the daemon will accept regex rules in
  destination filters; `pyvpn rules check` warns when it is missing. Simple
  wildcards such as `*.example.com` work without it.

## Configuration

The config is JSON, read from `/etc/pyvpn/config.json` by default. To
use another file, set `PYVPN_CONFIG` or pass `--config` to a command that
takes it (see Commands). **Targets** are
interfaces (exact names or patterns such as `tun*`); **policies** map apps
to an ordered list of targets:

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

- Targets are tried in order. `on_down` decides what happens once every
  target in the list is down: `default` (use the normal route) or `block`
  (kill switch).
- Each app selector uses exactly one of `exe`, `name`, `unit`, `uid`,
  `user`, `flatpak` or `snap`. Reusable lists go in `app_groups` and are
  referenced as `"group:<name>"`.
- A policy needs `apps`, `domains` or both. With only `apps`, all of their
  traffic uses the target. With both, only the matched destinations do.
  With only `domains`, those destinations use the target for every process.
  `domains` uses snake's rule syntax (domain rules, `asn:`, `cidr:`).

The full schema is in
[PLAN.md §5](https://github.com/irisariuan/pyvpn/blob/main/PLAN.md#5-configuration-sketch).

Check a config before using it:

```bash
pyvpn test /etc/pyvpn/config.json     # prints "ok" or a failure (the list of problems is still missing)
pyvpn policy --config /etc/pyvpn/config.json
```

## Commands

These work today without the daemon:

```bash
pyvpn test [config]                        # validate a config and its rules
pyvpn policy [name] [--config FILE]        # show configured policies
pyvpn rules check FILE                     # validate a destination rule file
pyvpn rules test FILE NAME...              # show which rule matches a DNS name
pyvpn rules import FILE                    # convert a foreign list to snake rules
pyvpn rules export POLICY [--config FILE]  # print a policy's rules
pyvpn install [--scope user]               # print the systemd unit for pyvpn-daemon (--write needs root)
pyvpn desktop --policy NAME                # print a .desktop launcher for a policy
```

These talk to `pyvpn-daemon` over its socket (`/run/pyvpn/pyvpn.sock` by
default; pass `--socket PATH` before the command to use another). If no daemon
is running, they exit with `cannot contact pyvpn daemon`:

```bash
pyvpn run -p "Japan browsing" -- firefox   # start an app inside a policy
pyvpn status                               # policies, active targets
pyvpn apps                                 # policy bindings by cgroup and UID
pyvpn audit                                # what each policy does and does not protect
pyvpn reload                               # re-read the config
pyvpn disable                              # remove all pyvpn rules and routes
```

Add `--json` before the command (`pyvpn --json status`) for machine-readable
output.

To try the daemon without root while the Linux backend is pending, run it in
dry-run mode. It logs each routing plan instead of installing it, and routes
and protects nothing:

```bash
pyvpn-daemon --backend dry-run --config config.json --socket /tmp/pyvpn.sock --state-dir /tmp/pyvpn-state
pyvpn --socket /tmp/pyvpn.sock status
```

## How it works

- A small **root daemon** owns nft, routes and cgroups. The CLI and
  `pyvpn run` run unprivileged and talk to it over a **unix socket**. `run`
  asks the daemon to put its own PID in the policy's cgroup, then `exec`s
  the command, so the app keeps your environment and desktop session.
- Apps are identified by cgroup v2 (`pyvpn.slice/p-<id>`, systemd units,
  Flatpak scopes) or by uid. An nft `output` chain matches them and sets a
  **fwmark**; an **`ip rule`** sends that mark to a per-policy routing table
  (`default dev <iface>`, or `unreachable` for the kill switch).
- A **netlink** watcher switches targets as soon as an interface goes up or
  down, with no polling.
- Each policy gets its own DNS stub, resolved through the policy's
  interface, so DNS follows the app. System DNS is left alone.
- pyvpn **fails closed**: with `on_down: block`, traffic is dropped while
  rules change, never sent out the default route.

Details: [PLAN.md §3](https://github.com/irisariuan/pyvpn/blob/main/PLAN.md#3-how-it-works).

## Development

```bash
git clone https://github.com/irisariuan/pyvpn && cd pyvpn
pip install -e '.[dev]'
ruff check . && ruff format --check .
mypy src
pytest                         # unit tests: no root, never touch the host network
```

Network-namespace integration tests run as root on Linux:

```bash
sudo .venv/bin/python -m pytest -m integration
```

CI runs the same command on every pull request; the unit suite above never
touches the host network.

Before contributing, read:

- [PLAN.md](https://github.com/irisariuan/pyvpn/blob/main/PLAN.md): design, scope and milestones (source of truth)
- [WORKSTREAMS.md](https://github.com/irisariuan/pyvpn/blob/main/WORKSTREAMS.md): which workstream owns which directory
- [AGENTS.md](https://github.com/irisariuan/pyvpn/blob/main/AGENTS.md): working rules (fail closed, test rules, commits, branch names)

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
