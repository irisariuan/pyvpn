---
title: Using pyvpn
description: Write pyvpn policies, start apps in them, check routing and leak protection, reload, and troubleshoot.
license: GPL-3.0-or-later
---

# Using pyvpn

This guide assumes `pyvpn-daemon` is installed and running; see the
[installation guide](install.md). Examples use a WireGuard interface `wg-jp`
and an OpenVPN interface `tun0`; use your own interface names.

- [How it fits together](#how-it-fits-together)
- [Writing a configuration](#writing-a-configuration)
- [Starting apps in a policy](#starting-apps-in-a-policy)
- [Checking what pyvpn does](#checking-what-pyvpn-does)
- [When a target goes down](#when-a-target-goes-down)
- [Changing the configuration](#changing-the-configuration)
- [DNS and leak protection](#dns-and-leak-protection)
- [Destination filters](#destination-filters)
- [Turning pyvpn off](#turning-pyvpn-off)
- [Not supported yet](#not-supported-yet)
- [Troubleshooting](#troubleshooting)

## How it fits together

- A **target** is a network interface that already exists, such as `wg-jp` or
  `tun0`. pyvpn never creates or connects VPNs; their own tools do that.
- A **policy** says which apps use which targets, in order, and what happens
  when all of them are down (`on_down`).
- Apps in a policy are tracked by **cgroup** (or by uid). The daemon marks
  their packets and routes them through the policy's own routing table, and
  points their DNS at a per-policy stub resolver.
- Everything else on the machine keeps using the normal route and the system
  resolver.

## Writing a configuration

The configuration is one JSON file: `/etc/pyvpn/config.json` by default, or
`$PYVPN_CONFIG`, or `--config FILE`. Always check it after editing:

```bash
pyvpn test /etc/pyvpn/config.json
```

A complete example:

```json
{
  "version": 1,
  "targets": [
    {"name": "jp", "interface": "wg-jp"},
    {"name": "nl", "interface": "tun*"},
    {"name": "office", "interface": "wlan1", "gateway": "auto"}
  ],
  "app_groups": [
    {"name": "browsers", "apps": [{"exe": "/usr/bin/firefox"}, {"flatpak": "com.google.Chrome"}]}
  ],
  "policies": [
    {"name": "Japan browsing", "targets": ["jp", "nl"], "on_down": "default",
     "apps": ["group:browsers", {"name": "steam"}],
     "leak": {"block_doh": true}},
    {"name": "Torrents", "targets": ["nl"], "on_down": "block",
     "apps": [{"exe": "/usr/bin/qbittorrent"}],
     "leak": {"ipv6": "block", "block_quic": true}},
    {"name": "Office", "targets": ["office"],
     "apps": [{"name": "ssh"}], "domains": ["corp.example", "cidr:10.20.0.0/16"]}
  ]
}
```

### Targets

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Name used in policies. Must be unique. |
| `interface` | yes | Interface name (`wg-jp`) or a glob pattern (`tun*`, `wg-jp*`). Use a pattern for VPN apps whose interface name changes on reconnect. |
| `gateway` | no | Next hop. Leave it out for point-to-point interfaces (`wg*`, `tun*`, `ppp*`). Use `"auto"` on Ethernet or Wi-Fi to take the interface's own default gateway; the target is only usable once one is found. Or give an IP address. |
| `probe` | no | `true` to check that traffic really gets through the interface (see [Health probes](#health-probes)). Default `false`. |

A target is **usable** when its link is up and has an address (and, with
`"gateway": "auto"`, a gateway). The daemon sees changes immediately through
netlink; it doesn't poll.

#### Health probes

Some VPN apps keep their interface up while the tunnel behind it is dead. For
those, set `"probe": true` on the target. The daemon then also opens a TCP
connection to the addresses in `settings.probe_targets` every
`settings.probe_interval` seconds, on a socket bound to the target's
interface, so a probe can never succeed over another route:

```json
"settings": {"probe_targets": ["1.1.1.1:443", "[2606:4700:4700::1111]:443"], "probe_interval": 15}
```

- A probe succeeds when a connection to any of the addresses opens (at most
  3 seconds each). Use IP addresses, not hostnames. The defaults are
  `["1.1.1.1:443"]` and 15 seconds.
- A probed target is **down until its first probe succeeds**, and again each
  time its interface appears or changes. The first success brings it up.
- After that, it goes down after **2 failed probes in a row** and comes back
  after **2 successful probes in a row**, so one lost probe doesn't switch
  the route.
- While a probed target is down, the policy uses its next target or its
  `on_down` (fallback or kill switch), as for a target whose link is down.
- Probes only run while the link is up; a link that goes down takes the
  target down at once.

### Policies

| Field | Default | Meaning |
|---|---|---|
| `name` | required | Unique name. `pyvpn run -p` uses it. |
| `targets` | required | Target names in priority order. The first usable one carries the traffic. |
| `on_down` | `"default"` | When **every** target is down: `"default"` falls back to the normal route; `"block"` drops the traffic (kill switch). |
| `apps` | | App selectors (below) or `"group:<name>"`. |
| `exclude_apps` | `[]` | Selectors for apps that should never match this policy. **Not enforced yet**; see [Not supported yet](#not-supported-yet). |
| `domains` | `[]` | Destination filters (see [below](#destination-filters)). |
| `leak` | see [DNS and leak protection](#dns-and-leak-protection) | DNS and leak options. |

A policy needs `apps`, `domains`, or both:

- **`apps` only:** all of those apps' traffic uses the target.
- **`apps` and `domains`:** only those apps' traffic to the matched
  destinations uses the target.
- **`domains` only:** traffic from **every process** to the matched
  destinations uses the target.

Policies are numbered by their position (1, 2, …). Up to 99 are allowed.

### App selectors

Each selector uses exactly one key:

| Selector | Example | Matches |
|---|---|---|
| `exe` | `{"exe": "/usr/bin/qbittorrent"}` | The executable's full path. |
| `name` | `{"name": "steam"}` | The process name. |
| `unit` | `{"unit": "transmission-daemon.service"}` | Processes in that systemd unit's cgroup. |
| `uid` / `user` | `{"uid": 1001}`, `{"user": "torrent"}` | Every process of that user. |
| `flatpak` | `{"flatpak": "org.mozilla.firefox"}` | A Flatpak app's sandbox. |
| `snap` | `{"snap": "firefox"}` | A Snap app. |

Reusable lists go in `app_groups` and are referenced as `"group:<name>"`.

The daemon's process watcher moves matching processes into the policy's cgroup
(`pyvpn.slice/p-<id>`) as they start, and scans running processes at startup
and after each reload. `uid`/`user` selectors are matched in nftables
directly, so nothing is moved.
Connections that are already open keep their old route; new ones follow the
policy.

## Starting apps in a policy

Apps matched by a selector are picked up automatically. To start any program
in a policy, whether or not a selector matches it, use `pyvpn run`. It works
as a normal user:

```bash
pyvpn run -p "Japan browsing" -- firefox
pyvpn run -p 2 -- qbittorrent           # by policy number
pyvpn run -p name:2 -- some-app         # a policy literally named "2"
```

`pyvpn run` asks the daemon to place its own process in the policy's cgroup,
then runs the command in its place, so the app keeps your environment and
desktop session, and every child process follows. A normal user can only place
their own process this way.

`pyvpn run` refuses to start the app if the policy's rules aren't installed
yet, so an app never starts unprotected.

### Desktop launchers

Make a menu entry that opens a shell in a policy:

```bash
pyvpn desktop --policy Torrents                  # print it
sudo pyvpn desktop --policy Torrents --write     # install to /usr/share/applications
pyvpn desktop --policy Torrents --scope user --write   # install for yourself only
```

## Checking what pyvpn does

```bash
pyvpn status
```

```text
daemon: enabled
1: Japan browsing: dev via wg-jp (jp)
2: Torrents: unreachable via - (-)
3: Office: main via - (-)
```

Each policy line is `<route> via <interface> (<target>)`:

| Route | Meaning |
|---|---|
| `dev` | Traffic leaves through the active target. |
| `main` | Every target is down and `on_down` is `default`: traffic uses the normal route. |
| `unreachable` | Every target is down and `on_down` is `block`: traffic is dropped (kill switch). |
| `not_installed` | No rules are installed: the daemon is disabled, or its first apply failed. |

A `last error:` line shows a problem the daemon is retrying or can't recover
from, such as a failed apply or a stopped process watcher.

```bash
pyvpn apps     # which cgroups and uids each policy covers
pyvpn audit    # what each policy protects, including DNS, plus warnings
```

```text
$ pyvpn apps
Japan browsing: cgroups=pyvpn.slice/p-1; uids=-
Torrents: cgroups=pyvpn.slice/p-2; uids=-

$ pyvpn audit
enabled: yes
policies: 3
backend: linux
dns:
  Japan browsing: via wg-jp
  Torrents: No active target interface
  Office: No active target interface
```

Here `Torrents` is blocked by its kill switch and `Office` has fallen back to
the normal route, so neither has a target for DNS.

Put `--json` before any command for machine-readable output, e.g.
`pyvpn --json status`. If the daemon uses a non-default socket, pass
`--socket PATH` before the command.

To see the installed rules themselves:

```bash
sudo nft list table inet pyvpn
ip rule | grep 0x5059
ip route show table 1001        # policy 1's table (1000 + policy number)
```

## When a target goes down

When a policy's active target goes down, the daemon switches within moments:

1. to the next usable target in `targets`;
2. if none is usable, to the normal route (`on_down: "default"`) or to
   `unreachable` (`on_down: "block"`);
3. back to the preferred target as soon as it's usable again.

Each policy table also keeps a low-priority `unreachable` route. So if an
interface vanishes before the daemon reacts, the policy's traffic is dropped
rather than leaked.

**If the daemon stops, its rules stay installed.** A kill switch keeps
blocking, but routes no longer follow target changes until the daemon runs
again.

## Changing the configuration

Edit the file, check it, then reload. Reloading needs root:

```bash
pyvpn test /etc/pyvpn/config.json
sudo pyvpn reload                 # or: sudo systemctl kill -s HUP pyvpn
```

The new rules replace the old ones atomically. If the new configuration is
rejected, the old one stays in force and `pyvpn reload` prints the reason.

Reloading has two limits:

- **Targets and `settings` can't change on reload.** Restart the daemon
  instead (`sudo systemctl restart pyvpn`).
- **Policy positions are reserved.** Once a policy's cgroup has held apps, a
  reload must keep that policy at the same position, because running apps are
  still in `pyvpn.slice/p-<id>`. Add new policies at the end.

## DNS and leak protection

Each policy with `dns_via_target` (on by default) gets its own DNS stub on
`127.0.0.1` and `::1`, port 5300 + the policy number (5301, 5302, …). nftables redirects all port-53 traffic **from that
policy's apps** to it, including hard-coded resolvers such as `8.8.8.8`. The
stub resolves through the policy's target and answers `SERVFAIL` instead of
falling back to another path. Other apps keep the system resolver. **pyvpn
doesn't change system DNS.**

| `leak` option | Default | Meaning |
|---|---|---|
| `dns_via_target` | `true` | Use the per-policy DNS stub. Needed for hostname rules in `domains`. |
| `dns_server` | Quad9 (`9.9.9.9`) | Upstream resolver as an IP address. For DoT/DoH use `tls-name@address`, e.g. `dns.quad9.net@9.9.9.9`. |
| `dns_protocol` | `"plain"` | `"plain"`, `"dot"` (DNS over TLS) or `"doh"` (DNS over HTTPS; needs `snakevpn[doh]`). |
| `block_doh` | `false` | Block known DoH servers, and answer Firefox's `use-application-dns.net` canary so it keeps using the stub. |
| `block_dot` | `false` | Block DNS over TLS (port 853). |
| `block_quic` | `false` | Block QUIC (UDP 443). Apps fall back to TCP. |
| `ipv6` | `"route"` | `"route"`: IPv6 also uses the target. `"block"`: the policy's IPv6 traffic is rejected (choose this if your target has no IPv6). `"off"`: pyvpn installs no IPv6 route for the policy. |

`pyvpn audit` shows each policy's DNS state and the leak blocks it requested.

## Destination filters

`domains` limits a policy to matching destinations, using snake's rule
language: plain domains (`corp.example` also matches its subdomains),
wildcards (`*.example.com`), and `cidr:10.20.0.0/16`. The policy's DNS stub
learns the addresses of matching names as apps look them up, so **hostname
rules need `dns_via_target: true`**.

Rule files can be checked and converted:

```bash
pyvpn rules check work.rules                 # validate a rule file
pyvpn rules test work.rules www.corp.example # which rule matches a name
pyvpn rules import adguard-list.txt          # convert hosts/AdGuard/dnsmasq lists
pyvpn rules export Office --config /etc/pyvpn/config.json
```

## Turning pyvpn off

```bash
sudo pyvpn disable
```

This removes every pyvpn rule and route. Apps go back to the normal route
immediately, and kill switches stop blocking. The daemon remembers it's
disabled, even across restarts.

There's no `pyvpn enable` command yet. To turn routing back on, call the
daemon's `enable` method directly:

```bash
sudo python3 -c '
import json, socket
s = socket.socket(socket.AF_UNIX); s.connect("/run/pyvpn/pyvpn.sock")
s.sendall(b"{\"id\": 1, \"method\": \"enable\", \"params\": {}}\n"); print(s.recv(4096).decode())'
```

## Not supported yet

The daemon refuses these, or they have no effect yet. Don't rely on them:

| Feature | What happens |
|---|---|
| `"isolation": "netns"` on a policy | The daemon refuses the config (`isolation 'netns' is not supported by the daemon yet`). |
| `asn:` rules in `domains` | Refused: nothing fetches the ASN prefix cache yet. Use `cidr:` rules instead. |
| `drop:` rules and snake's per-device rules | Refused by the daemon; `pyvpn rules check` reports them. |
| `pyvpn enable` | Missing; see [Turning pyvpn off](#turning-pyvpn-off). |
| `exclude_apps` | Accepted, but the daemon doesn't enforce it: excluded apps are still routed by the policy. |
| Problem list from `pyvpn test` | For JSON or schema errors it prints only `configuration validation failed`. Destination rule errors are listed per rule, followed by `errors found`. |

## Troubleshooting

| Symptom | What to check |
|---|---|
| `pyvpn run` says `routing rules are not installed yet` | The daemon's apply failed or it's disabled. `pyvpn status` shows `last error:`; check `journalctl -u pyvpn`. |
| A policy shows `unreachable` although the VPN is up | The interface name doesn't match `interface` (try a pattern like `tun*`), or `"gateway": "auto"` found no gateway. Check `ip -br addr`. With `"probe": true`, the probes may be failing: the daemon log says `probes fail through <interface>`. Check that the `settings.probe_targets` addresses accept TCP connections through the VPN, e.g. `curl --interface tun0 https://1.1.1.1`. |
| An app isn't routed | Check that `pyvpn apps` lists its policy, and that the process is in the cgroup: `cat /proc/<pid>/cgroup` should show `pyvpn.slice/p-<id>`. Connections opened before it was placed keep their old route; restart the app or use `pyvpn run`. |
| DNS fails inside a policy | `pyvpn audit` shows the DNS state. The stub answers `SERVFAIL` when the target is down, by design. |
| `last error: process watcher failed` | The daemon can't subscribe to process events. It needs root, in the host's network namespace. `pyvpn run` still works. |
| Everything is blocked after uninstalling | Rules stay after the daemon stops. Run `sudo pyvpn disable` with the daemon running, or remove them by hand: `sudo nft delete table inet pyvpn`, then delete the `ip rule`s with fwmark `0x5059…`. |
