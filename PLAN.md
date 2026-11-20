# pyvpn — plan

**App-based (process-based) policy routing** for the machine it runs on,
packaged for PyPI. It is the client-side counterpart of
[snake](https://github.com/irisariuan/snake): snake chooses a tunnel per
*device* on a router; pyvpn chooses an **outgoing interface per process** on
a Linux laptop or desktop.

> "Firefox and Steam leave through `wg-jp`, qBittorrent only through `tun0`
> with a kill switch, `ssh` to the office through `wlan1`, everything else
> through the normal default route."

**pyvpn does not run or maintain VPN connections.** WireGuard, OpenVPN, a
provider's app, a second NIC or a phone tether bring their interfaces up
themselves. pyvpn only makes sure each app's traffic (and its DNS) leaves
through the right interface. When that interface is missing or down, the
policy either falls back to the next interface, falls back to the default
route, or blocks (kill switch).

---

## 1. Name and distribution

* `pyvpn` is **already taken on PyPI** (checked 2026-11-20). Free names:
  `snakevpn`, `policyvpn`, `splitvpn`. **Proposal: publish as `snakevpn`**;
  the import package and command stay `pyvpn` (`pip install snakevpn` →
  `pyvpn …`).
* Python ≥ 3.11, `src/` layout, `pyproject.toml` with hatchling, one console
  script `pyvpn`. Pure-Python wheel.
* Dependencies: `pyroute2` (netlink: routes, rules, link/address events,
  sock_diag, process-event connector), `dnspython` (per-app DNS stubs,
  DoT/DoH upstreams), `pydantic` v2 (config). Extra `snakevpn[ui]` →
  `aiohttp` for a local web UI.
* Release: on a `v*` tag, GitHub Actions runs the tests, builds sdist and
  wheel, and publishes with **PyPI Trusted Publishing** (no stored token).

## 2. Platform scope

Per-process routing needs the kernel to tell which process a packet belongs
to. Linux can do this from Python (cgroup v2 + nftables + policy routing).
macOS needs a signed Network Extension, and Windows a WFP callout or
WinDivert proxy. **Linux only for v0.x**, with a `platform/` interface so
other backends can come later.

## 3. How it works

```
process ── in cgroup pyvpn.slice/p-<id>, or matched by uid / unit cgroup
   │
   ├─ DNS (port 53) ──► nft redirect ─► per-policy stub 127.0.0.1:53<id>
   │                                     resolves via the policy's interface,
   │                                     fills dest sets before replying
   │
   └─ packets ──► nft  table inet pyvpn  chain output (type route, hook output)
                    LAN/loopback → accept unchanged
                    socket cgroupv2 "pyvpn.slice/p-<id>" [ip daddr ∈ dest sets] → meta mark P
                    ct mark save/restore (a connection keeps its interface)
                    leak rejects for P: DoT, DoH IPs, QUIC, IPv6 (per policy)
              ──► ip rule pref 5200+id  fwmark P → table 1000+id
                    table 1000+id: default dev <iface> [via <gw>]   (active interface)
                                 | unreachable                       (kill switch)
                                 | (empty → main table)              (fall back to default route)
              ──► nft postrouting: masquerade marked traffic to the interface's address
                    (the source address was chosen for the default route before re-routing)
```

### 3.1 Interfaces (targets)

A *target* is just an interface name, plus an optional gateway:

* **Point-to-point** (`tun0`, `wg0`, `ppp0`, a provider's `proton0`):
  `default dev tun0` is enough.
* **Broadcast** (`eth1`, `wlan1`, `usb0` tether): needs a next hop. pyvpn
  learns it from that interface's own default route or DHCP lease (main
  table, or the route NetworkManager installs with a metric), or uses the
  configured `gateway`.
* **Patterns** (`tun*`, `wg-jp*`): for VPN apps whose interface name changes
  on every reconnect.

pyvpn **watches netlink** (link up/down, address add/remove, route changes)
and reconciles at once. When `tun0` disappears because the VPN app
reconnects, the policy table is switched to the next target, the default
route, or `unreachable`. When `tun0` comes back, the route is re-installed
within milliseconds. No polling is needed for this.

### 3.2 Choosing between several targets (optional)

A policy lists targets in priority order. The first *usable* one wins:

* **usable = link is up and has an address** (always checked, from netlink
  events)
* optional **reachability probe**: TCP connect to `probe_targets` through
  that interface (socket bound with `SO_BINDTODEVICE`), for VPNs that keep
  the interface up while the tunnel behind it is dead
* optional **exit-country check** (snake's `expected_country`, geo URL
  through the interface)

Fail-back hold and the latency-based selection are ported from snake's
`health` module, but they are opt-in. The default is plain link state.

### 3.3 Identifying apps

| Selector | Example | How |
|---|---|---|
| launched by pyvpn | `pyvpn run -p JP -- firefox` | the child starts in cgroup `pyvpn.slice/p-JP` (via the daemon, or a transient `systemd-run --scope`), and every descendant follows |
| executable | `exe: /usr/bin/qbittorrent`, `name: steam` | **process watcher** (netlink proc connector `PROC_EVENT_EXEC`, with a `/proc` scan at start) moves matching PIDs into the policy's cgroup |
| systemd unit / slice | `unit: transmission-daemon.service` | match its existing cgroup path; nothing is moved |
| user | `uid: 1001`, `user: torrent` | nft `meta skuid` |
| Flatpak / Snap | `flatpak: org.mozilla.firefox` | its `app-flatpak-…scope` cgroup |
| exclusions | `exclude_apps: [...]` | the same selectors; an excluded app never matches |

Already-open sockets keep their route; new connections follow the new
cgroup (as in snake: "connections keep their route").

### 3.4 Destination filters (optional, from snake)

A policy with only apps sends **all** of their traffic through the target. A
policy with apps **and** destination rules sends only the matched
destinations (snake's domain rules, `asn:`, `cidr:`) through it. A policy
with destination rules and no apps applies those destinations to every
process. Domain matches come from the per-policy DNS stub: the answered
addresses go into nft sets *before* the reply is released, as snake's DNS
inspector does.

### 3.5 Per-app DNS and leaks

* Each policy gets its own stub (`127.0.0.1:53<id>`). nft redirects port 53
  **from that policy's apps** to it, which also catches hard-coded `8.8.8.8`.
  The stub forwards through the policy's interface (bound socket; plain, DoT
  or DoH; SERVFAIL rather than falling back to another path).
* Other apps keep the system resolver. **pyvpn does not take over system
  DNS.**
* Per-policy leak toggles (snake's): block DoT 853, block known DoH
  addresses, DoH canary NXDOMAIN, block QUIC, IPv6 `route`/`block`/`off`.
* `pyvpn audit` lists, per policy, what is and is not protected.

### 3.6 Strict isolation (optional)

`isolation: netns`: the app runs in its own network namespace joined to the
host by a veth pair. Host-side rules forward that veth **only** to the
policy's target, so the app cannot leak even if the pyvpn daemon dies. This
works only for apps launched through `pyvpn run`.

## 4. What carries over from snake

| snake | pyvpn |
|---|---|
| Rule language (`match`), `.rules` files, AdGuard/hosts/dnsmasq import, rule lists | ported unchanged, with snake's test vectors (destination filters) |
| Policies: ordered tunnels, kill switch, first-match-wins order, leak toggles | the same, with *targets = interfaces* |
| Health: probes through the tunnel, exit country, fail-back hold, latency selection | ported, optional |
| Mark / table / priority conventions, atomic rule application | nftables JSON transactions (`nft -j -f -`) + pyroute2 |
| Devices / groups | **apps / app groups** |
| Saved WireGuard / OpenVPN tunnels, firmware VPN clients | **dropped**: pyvpn does not manage connections |
| Router-only parts (dnsmasq ipset, Merlin hooks, nvram, Broadcom marks, self-update) | dropped |
| `session:` / `if:then:else:` rules, SNI sniffing, WebRTC | later, if wanted |

## 5. Configuration (sketch)

```json
{
  "version": 1,
  "targets": [
    {"name": "jp",     "interface": "wg-jp"},
    {"name": "nl",     "interface": "tun*", "probe": true},
    {"name": "office", "interface": "wlan1", "gateway": "auto"}
  ],
  "app_groups": [{"name": "browsers", "apps": [{"exe": "/usr/bin/firefox"}, {"flatpak": "com.google.Chrome"}]}],
  "policies": [
    {"name": "Japan browsing", "targets": ["jp", "nl"], "on_down": "default",
     "apps": ["group:browsers", {"name": "steam"}],
     "leak": {"dns_via_target": true, "dns_server": "9.9.9.9", "dns_protocol": "dot",
              "block_doh": true, "block_dot": true, "ipv6": "route"}},
    {"name": "Torrents", "targets": ["nl"], "on_down": "block", "isolation": "netns",
     "apps": [{"exe": "/usr/bin/qbittorrent"}], "leak": {"ipv6": "block"}},
    {"name": "Office", "targets": ["office"],
     "apps": [{"name": "ssh"}, {"name": "remmina"}], "domains": ["corp.example", "cidr:10.20.0.0/16"]}
  ],
  "settings": {"probe_targets": ["1.1.1.1:443"], "probe_interval": 15}
}
```

`on_down`: `next` (the next target, implied by the list), then `default`
(normal route) or `block` (kill switch).

## 6. Package layout

```
src/pyvpn/
  cli/          run, status, apps (live PID → policy → interface), test, policy, rules, install, disable
  config/       pydantic models, migrations, snake .rules import
  apps/         selectors, process watcher (proc connector), cgroup v2 manager, run launcher, netns launcher
  targets/      interface resolution (names/patterns, gateway discovery), netlink watcher, optional probes
  routing/      policy tables + ip rules (pyroute2), reconcile loop
  netfilter/    nft ruleset builder (pure, golden-tested) + atomic apply
  dns/          per-policy stubs, upstream plain/DoT/DoH bound to an interface, answer → set
  match/        rule language (port of snake internal/match)
  rulefile/     .rules + converters
  daemon/       state, event loop (asyncio), unix-socket API, persistence
  platform/     base protocol; linux/ now
```

The root daemon owns nft, routes and cgroups. The CLI and `pyvpn run` are
unprivileged: `run` asks the daemon over the unix socket to place its own
PID in the policy's cgroup, then `exec`s the command, so the user's
environment and desktop session are kept.

## 7. Milestones

| # | Milestone | Done when |
|---|---|---|
| **M0** | Scaffold: pyproject, ruff, mypy, pytest, CI (3.11–3.13), Trusted Publishing workflow | `pip install snakevpn` from TestPyPI prints a version |
| **M1** | **Core app routing**: daemon + unix socket, cgroup manager, `pyvpn run -p P -- cmd`, nft output chain with `socket cgroupv2` marks, per-policy table + `ip rule`, masquerade, LAN exemption, kill switch, clean teardown, `pyvpn disable` | in a netns test bed, `pyvpn run -p X -- curl` leaves via the target and plain `curl` via the default route; with the target down and `on_down: block`, nothing leaks |
| **M2** | **Targets**: netlink watcher, interface patterns, gateway discovery for broadcast interfaces, ordered fallback, optional TCP probes / exit country | deleting and re-creating `tun0` switches the policy and switches back within 100 ms, with no leak in between |
| **M3** | **Selectors + watcher**: exe/name/unit/uid/flatpak, proc-connector watcher, app groups, exclusions, `pyvpn apps` | a normally started `/usr/bin/foo` lands in its policy within 50 ms, and its children follow |
| **M4** | **Per-app DNS + leak protection**: per-policy stubs, port-53 redirect per cgroup, resolver bound to the target, DoH/DoT/QUIC blocks, canaries, IPv6 modes, `pyvpn audit` | DNS leak tests: a routed app's queries only leave through its target |
| **M5** | **Destination filters**: port snake `match` + `rulefile` with its test vectors, ASN/CIDR sets, `pyvpn rules check/test/import/export` | snake's vectors pass; app + domain policies route only the matched destinations |
| **M6** | Strict netns isolation, `pyvpn install` (systemd unit), `.desktop` "open with policy" helper, `--json` output | **v0.1 public release** |
| **M7** | Later: web UI / tray, `session:`/`if:` per app, SNI sniffing, macOS / Windows backends | — |

## 8. Testing

* **Unit (no root):** nft ruleset generation (golden JSON), route/rule plans,
  target selection with fake netlink events, selector matching against fake
  `/proc` trees, rule engine (snake's vectors), config migrations.
* **Integration (root, GitHub ubuntu-24.04 runners with sudo):** a pytest
  fixture builds namespaces: "host" with a veth "WAN" to an "internet" ns,
  and a second veth or WireGuard link that stands in for a VPN interface
  (the fixture creates it, pyvpn does not). Tests launch processes through
  `pyvpn run`, delete and re-create interfaces, and assert by capture which
  interface the traffic and DNS left through.

## 9. Risks

* **cgroup v2 required** (the default on current distros). On v1/hybrid
  systems, fall back to UID policies with a warning.
* **Moving running processes** between cgroups can fight systemd scopes.
  Prefer `pyvpn run` / transient scopes; use the exe watcher only where
  configured.
* **VPN apps with their own kill switches** (their own nft tables, or
  `ip rule` that sends everything into the tunnel) can override us. Use our
  own table, rule priorities below theirs where possible, and document the
  ranges. `pyvpn audit` detects competing rules.
* **Interface flaps**: a short window between the interface vanishing and the
  table update. With `on_down: block` the table holds `unreachable` while
  no target is usable, so the gap fails closed.
* **Root daemon**: keep it small; everything else runs unprivileged.

## 10. Open questions

1. Linux only for v0.x — OK?
2. Should running processes be moved automatically by exe name (watcher), or
   only apps launched through `pyvpn run` / systemd units?
3. Should a policy have several targets with fallback, or exactly one
   interface (simpler)?
4. PyPI name: `snakevpn` (proposed), `policyvpn`, or another?
5. Keep snake's domain-rule language for optional destination filters?
