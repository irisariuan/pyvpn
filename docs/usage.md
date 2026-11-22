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

It prints `ok`, or one line per problem followed by `errors found` (exit
status 1):

```text
/etc/pyvpn/config.json: error: targets.0.interface: Field required
/etc/pyvpn/config.json: error: policies.0.on_down: Input should be 'default' or 'block'
errors found
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
| `exclude_apps` | `[]` | Selectors for apps that never match this policy (see [Excluding apps](#excluding-apps)). |
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

### Excluding apps

`exclude_apps` takes the same selectors (and `"group:<name>"`). Other
policies still apply to an excluded process.

- **Policy with `apps`:** an excluded process is never placed in the
  policy; if another policy's `apps` match it, that policy takes it. With
  exclusions, the policy's `uid`/`user` app selectors are placed by the
  process watcher instead of being matched in nftables.
  **Limit:** a process is never moved *out* of the policy. An excluded
  program started from something the policy already routes (a shell, your
  desktop session, `pyvpn run`) stays routed. Moving it out would let
  whatever it runs next escape the policy and its kill switch. `pyvpn test`
  warns about this.

  ```json
  {"name": "Torrents", "targets": ["jp"], "apps": [{"user": "torrent"}],
   "exclude_apps": [{"name": "ssh"}]}
  ```

- **Policy with only `domains`** (applies to every process): only `uid` and
  `user` work. Use them to keep a userspace VPN client's own traffic on the
  normal route, for example by running it as its own user. The daemon and
  `pyvpn test` refuse `exe`, `name`, `unit`, `flatpak` and `snap` here
  (see [Not supported yet](#not-supported-yet)).

  ```json
  {"name": "Corp", "targets": ["corp"], "domains": ["cidr:10.0.0.0/8"],
   "exclude_apps": [{"user": "openvpn"}]}
  ```

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
wildcards (`*.example.com`), `cidr:10.20.0.0/16` and `asn:2906` (every
prefix an autonomous system announces). The policy's DNS stub learns the
addresses of matching names as apps look them up, so **hostname rules need
`dns_via_target: true`**. `cidr:` and `asn:` rules need no DNS.

### The ASN prefix cache

The daemon never downloads anything. `asn:` (and `drop:asn:`) rules use the prefixes in
an on-disk cache, `/var/lib/pyvpn/asn/AS<n>.json`, which you fill with
`pyvpn asn refresh`. It downloads each AS's announced prefixes from
[RIPEstat](https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes)
(what the RIPE RIS route collectors saw it announce in the last two weeks),
checks them, and replaces the cache file. It changes no routing and only needs
write access to the cache directory, so with the default directory you run
it with `sudo`:

```bash
sudo pyvpn asn refresh        # fetch the ASNs your config uses
sudo pyvpn reload             # route by the new prefixes
pyvpn asn status              # cached prefixes and their age
```

```text
ASN cache: /var/lib/pyvpn/asn (refresh after 24.0 h, refused after 7.0 days)
asn:2906: 518 prefixes, fetched 3 min ago (fresh)
ok
```

Both take ASNs as arguments (`pyvpn asn refresh AS2906`) instead of reading
the config, and `--asn-cache DIR` for another directory. `refresh` skips
entries younger than a day unless you pass `--force`.

Cache entries are refused, and the daemon won't load a config that needs
them (it keeps the previous one on reload), when they are:

- **missing**, or not valid (a prefix that isn't a network, shorter than
  `/8` for IPv4 or `/16` for IPv6, an empty list, or a file for another AS);
- **stale**: fetched more than 7 days ago, or dated in the future;
- **not trusted**: the daemon only reads files owned by its own user (root)
  that group and others can't write, so other users can't plant prefixes.

pyvpn never routes `asn:` rules by a guess. `pyvpn test` and
`pyvpn rules check` report these entries as errors (warnings for a rule
file). While the daemon runs, it checks the cache every hour: when an entry
it uses goes stale, `pyvpn status` shows it as `last error: ASN cache: …`.
The installed prefixes stay in force until a reload, because removing them
would send those destinations out the default route. Refresh the cache
regularly, for example from a daily systemd timer or cron job that runs
`pyvpn asn refresh && pyvpn reload` as root.

`drop:` blocks a destination for the policy's apps instead of routing it:
`drop:ads.example` (its subdomains too), `drop:cidr:192.0.2.0/24` or
`drop:ip:2001:db8::7`. Connections to a dropped address are rejected right
away, including ones opened before the address was learned. Policies are
checked in order, so an earlier policy that routes the same address for the
same app wins. Local network, loopback and multicast addresses are never
blocked.

Rule files can be checked and converted:

```bash
pyvpn rules check work.rules                 # validate a rule file (and its asn: cache entries)
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

To turn routing back on:

```bash
sudo pyvpn enable
```

The daemon reinstalls the current configuration's rules. If that fails,
`pyvpn status` shows `last error:` and the daemon keeps retrying.

## Not supported yet

The daemon refuses these, or they have no effect yet. Don't rely on them:

| Feature | What happens |
|---|---|
| `"isolation": "netns"` on a policy | The daemon refuses the config (`isolation 'netns' is not supported by the daemon yet`). |
| snake's per-device rules (`session:`, `route:`, `drop[...]:`, `if:` with `then:`/`else:`) | Refused by the daemon; `pyvpn rules check` reports them. |
| `exclude_apps` by `exe`, `name`, `unit`, `flatpak` or `snap` on a policy with only `domains` | Refused by the daemon and `pyvpn test`. Exclude by `uid` or `user` instead. |
| `exclude_apps` for programs started from inside a policy with `apps` | They stay routed by the policy; exclusions only stop a process from being placed. `pyvpn test` warns. |

## Troubleshooting

| Symptom | What to check |
|---|---|
| `pyvpn run` says `routing rules are not installed yet` | The daemon's apply failed or it's disabled. `pyvpn status` shows `last error:`; check `journalctl -u pyvpn`. |
| A policy shows `unreachable` although the VPN is up | The interface name doesn't match `interface` (try a pattern like `tun*`), or `"gateway": "auto"` found no gateway. Check `ip -br addr`. With `"probe": true`, the probes may be failing: the daemon log says `probes fail through <interface>`. Check that the `settings.probe_targets` addresses accept TCP connections through the VPN, e.g. `curl --interface tun0 https://1.1.1.1`. |
| An app isn't routed | Check that `pyvpn apps` lists its policy, and that the process is in the cgroup: `cat /proc/<pid>/cgroup` should show `pyvpn.slice/p-<id>`. Connections opened before it was placed keep their old route; restart the app or use `pyvpn run`. |
| DNS fails inside a policy | `pyvpn audit` shows the DNS state. The stub answers `SERVFAIL` when the target is down, by design. |
| `cannot activate destination rules: … asn:…` or `last error: ASN cache: …` | The ASN cache entry is missing, stale or not owned by root. Run `sudo pyvpn asn refresh`, then `sudo pyvpn reload`; `pyvpn asn status` shows each entry. |
| `last error: process watcher failed` | The daemon can't subscribe to process events. It needs root, in the host's network namespace. `pyvpn run` still works. |
| Everything is blocked after uninstalling | Rules stay after the daemon stops. Run `sudo pyvpn disable` with the daemon running, or remove them by hand: `sudo nft delete table inet pyvpn`, then delete the `ip rule`s with fwmark `0x5059…`. |
