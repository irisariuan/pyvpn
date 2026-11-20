# pyvpn — plan

**App-based (process-based) VPN routing** for the machine it runs on,
packaged for PyPI. It is the client-side counterpart of
[snake](https://github.com/irisariuan/snake): snake chooses a tunnel per
*device* on a router; pyvpn chooses a tunnel per *process* on a laptop or
desktop.

> "Firefox and Steam go through the Japan WireGuard, qBittorrent only through
> the OpenVPN with a kill switch, everything else on the normal connection."
> Each policy can also narrow by destination (snake's domain / ASN / CIDR
> rules), fail over between tunnels, and prevent DNS / IPv6 leaks per app.

---

## 1. Name and distribution

* `pyvpn` is **already taken on PyPI** (checked 2026-11-20). Free names:
  `snakevpn`, `policyvpn`, `splitvpn`. **Proposal: publish as `snakevpn`**;
  the import package and command stay `pyvpn` (`pip install snakevpn` →
  `pyvpn …`).
* Python ≥ 3.11, `src/` layout, `pyproject.toml` with hatchling, one console
  script `pyvpn`. Pure-Python wheel.
* Dependencies: `dnspython` (DNS, DoT/DoH), `pyroute2` (Linux: netlink
  routes, rules, links, WireGuard, sock_diag, the process-event connector),
  `pydantic` v2 (config). Extra `snakevpn[ui]` → `aiohttp` for a local web UI.
* Release: on a `v*` tag, GitHub Actions runs the tests, builds sdist and
  wheel, and publishes with **PyPI Trusted Publishing** (no stored token).

## 2. Platform reality

Per-process routing needs kernel help to tell which process a packet belongs to:

| OS | Mechanism | From Python? | Plan |
|---|---|---|---|
| **Linux** | cgroup v2 + nftables `socket cgroupv2` → fwmark → `ip rule`; or a network namespace per app | **Yes**, fully | **Primary target** |
| macOS | Network Extension (`NEAppProxyProvider` / per-app VPN): needs a signed Swift system extension | No (needs a native helper) | Later: destination-only policies, or a small signed helper |
| Windows | WFP ALE layers know the app ID; redirecting needs a callout driver or WinDivert + a proxy | Partly (WinDivert via `pydivert`, but it means proxying every flow) | Later / experimental |

**Decision: Linux first and complete; keep a `platform/` abstraction so macOS
and Windows backends can come later.** It also makes sense to make Linux
packages run as a systemd service.

## 3. How app routing works on Linux

### 3.1 Identifying apps

A policy selects apps by any of:

| Selector | Example | How |
|---|---|---|
| launched by pyvpn | `pyvpn run -p JP -- firefox` | the child starts inside cgroup `pyvpn.slice/p-JP`, so every descendant is included |
| executable | `exe: /usr/bin/qbittorrent`, `name: steam` | **process watcher** (netlink proc connector `PROC_EVENT_EXEC`, with a `/proc` scan at start) moves matching PIDs and their future children into the policy's cgroup |
| systemd unit / slice | `unit: transmission-daemon.service` | match the existing cgroup path directly; nothing is moved |
| user | `uid: 1001` / `user: torrent` | nft `meta skuid` |
| Flatpak / Snap app id | `flatpak: org.mozilla.firefox` | its scope cgroup `app-flatpak-org.mozilla.firefox-*.scope` |
| exclusions | `exclude: [...]` | the same selectors; an excluded app never matches the policy |

The watcher runs as root and reacts to `exec` events within milliseconds.
Already-open sockets keep their route; new connections are routed by the new
cgroup (as snake does: "connections keep their route").

### 3.2 Routing (default "mark" mode)

```
process in cgroup pyvpn.slice/p-<id>  (or matched by uid / unit cgroup)
   ─► nft table inet pyvpn, chain output (type route, hook output):
        socket cgroupv2 level 2 "pyvpn.slice/p-<id>" [and daddr ∈ P's dest sets] → meta mark set P
        ct mark restore / save, so a connection keeps its tunnel
        leak rejects for P: DoT 853, DoH IPs, QUIC, IPv6 (per policy)
   ─► ip rule pref 5200+id  fwmark P → table 1000+id
        table 1000+id: default dev <active tunnel> | unreachable (kill switch)
   ─► nft postrouting: masquerade out of the tunnel (the source was chosen for WAN before rerouting)
```

* `type route` output chains make the kernel re-route a packet after its mark
  changes. This is how per-app routing works without touching other apps.
* LAN and loopback destinations are exempt by default (a `route_lan` option
  turns that off).
* An app with no destination rules sends everything through the tunnel. An
  app with destination rules sends only those destinations through it
  (snake's semantics, with "device" replaced by "app").

### 3.3 Strict "netns" mode (optional per policy)

`isolation: netns` runs the app in its own network namespace whose only way
out is the tunnel (a WireGuard interface moved into the namespace, or a veth
pair to the root namespace for OpenVPN). The kill switch is then structural:
the app cannot leak even if pyvpn crashes. Costs: only for apps that pyvpn
launches, and no LAN access unless asked for. Good for torrent clients.

### 3.4 Per-app DNS

DNS must follow the app. Otherwise the CDN answers are for your real location
and the queries leak:

* Each policy gets its own stub listener (`127.0.0.1:53<id>`, or a
  `127.0.0.54+id` address). nft redirects UDP/TCP 53 **from the policy's
  apps** to it, so hard-coded `8.8.8.8` is caught too.
* That stub resolves **through the policy's tunnel** (socket bound with
  `SO_BINDTODEVICE` / fwmark; plain, DoT or DoH; SERVFAIL rather than falling
  back). When the policy has destination rules, it also adds the answered
  addresses to the policy's nft sets *before* replying, as snake's DNS
  inspector does.
* Apps without a policy keep using the system resolver unchanged. **pyvpn does
  not take over system DNS** (that is fragile on desktops), except in an
  optional "destination policies for every app" mode.
* Browser DoH: canary `use-application-dns.net` → NXDOMAIN, plus blocking of
  known DoH addresses and DoT for policy apps (snake's preset lists). DoH
  then goes through the tunnel at worst, never out the WAN.

## 4. What carries over from snake

| snake | pyvpn |
|---|---|
| Rule language (`match`): suffix/exact, globs, `~kw`, `/re/`, `!`, `drop:`, CNAME chains, `asn:`/`cidr:` | **ported as is**, with snake's test vectors; used for a policy's optional destination filter |
| `.rules` files, AdGuard/hosts/dnsmasq import, rule lists | ported |
| Tunnels list with failover, fail-back hold, `latency`/`speed`/`balanced` selection, exit-country check, kill switch | ported (`health/`) |
| Saved WireGuard / OpenVPN tunnels (`wgx`, `ovx`) | managed tunnels: WireGuard via pyroute2, OpenVPN subprocess (`route-nopull`, management socket) + "existing interface" tunnels from other VPN apps |
| Devices / groups | **apps / app groups** |
| `session:` / `if:then:else:` rules | later, keyed by app instead of device |
| Router-only parts (dnsmasq ipset, Merlin hooks, nvram, Broadcom marks, VPN server clients, self-update) | dropped |

## 5. Configuration (sketch)

```json
{
  "version": 1,
  "tunnels": [
    {"name": "jp-wg",   "type": "wireguard", "conf": "/etc/pyvpn/jp.conf"},
    {"name": "nl-ovpn", "type": "openvpn",   "conf": "/etc/pyvpn/nl.ovpn", "auth": "/etc/pyvpn/nl.auth"},
    {"name": "work",    "type": "existing",  "interface": "tun0"}
  ],
  "app_groups": [{"name": "browsers", "apps": [{"exe": "/usr/bin/firefox"}, {"flatpak": "com.google.Chrome"}]}],
  "policies": [
    {"name": "Japan browsing", "tunnels": ["jp-wg", "nl-ovpn"], "kill_switch": false,
     "apps": ["group:browsers", {"name": "steam"}], "exclude_apps": [],
     "domains": [], "expected_country": "jp",
     "leak": {"dns_via_tunnel": true, "dns_server": "9.9.9.9", "dns_protocol": "dot",
              "block_doh": true, "block_dot": true, "ipv6": "tunnel"}},
    {"name": "Torrents", "tunnels": ["nl-ovpn"], "kill_switch": true, "isolation": "netns",
     "apps": [{"exe": "/usr/bin/qbittorrent"}], "leak": {"ipv6": "block"}},
    {"name": "Work only for corp", "tunnels": ["work"],
     "apps": [{"user": "alice"}], "domains": ["corp.example", "cidr:10.20.0.0/16"]}
  ],
  "settings": {"health_interval": 15, "probe_targets": ["1.1.1.1:443"]}
}
```

## 6. Package layout

```
src/pyvpn/
  cli/          run, status, test, apps (who-is-routed-where), policy, rules, tunnel, install, disable
  config/       pydantic models, migrations, snake config/rules import
  apps/         selectors, process watcher (proc connector), cgroup v2 manager, `run` launcher, netns launcher
  match/        rule language (port of snake internal/match)
  rulefile/     .rules + converters
  dns/          per-policy stub servers, upstream plain/DoT/DoH bound to tunnel, answer → set
  engine/       daemon state, reconcile loop, persistence
  health/       probes, geo, scoring, failover state machine
  tunnels/      existing / wireguard / openvpn
  platform/     base protocol; linux/ (nft JSON via `nft -j -f -`, pyroute2); darwin/, windows/ later
  api/          unix-socket JSON API; optional aiohttp UI
```

The root daemon owns nft, routes, cgroups and tunnels. `pyvpn run` is
unprivileged: it asks the daemon over the unix socket to create a cgroup and
move its own PID there, then `exec`s the command, so the user's environment
and Wayland/X11 session are kept.

## 7. Milestones

| # | Milestone | Done when |
|---|---|---|
| **M0** | Scaffold: pyproject, ruff, mypy, pytest, CI (3.11–3.13), Trusted Publishing workflow | `pip install snakevpn` from TestPyPI prints a version |
| **M1** | **App routing core (Linux, existing-interface tunnel)**: daemon + unix socket, cgroup manager, `pyvpn run -p P -- cmd`, nft output chain with `socket cgroupv2` marks, `ip rule`/table per policy, masquerade, kill switch, clean teardown, `pyvpn disable` | in a netns test bed, `pyvpn run -p X -- curl` exits via the tunnel interface and plain `curl` via WAN; with the tunnel down and the kill switch on, the routed curl fails and nothing leaks |
| **M2** | **Selectors + process watcher**: exe/name/unit/uid/flatpak selectors, proc-connector watcher, app groups, exclusions, `pyvpn apps` (live view: PID → policy → tunnel) | starting `/usr/bin/foo` normally lands it in its policy within 50 ms; its children follow |
| **M3** | **Per-app DNS + leak protection**: per-policy stub, nft port-53 redirect per cgroup, resolver through the tunnel (plain/DoT/DoH), DoH/DoT/QUIC blocks, canaries, IPv6 modes, `pyvpn audit` | DNS leak tests in netns: the routed app's queries only leave through the tunnel |
| **M4** | **Managed tunnels + health + failover**: WireGuard (pyroute2), OpenVPN subprocess, probes bound to the tunnel, exit country, priority failover / fail-back / auto selection | killing a tunnel moves the policy within one health interval |
| **M5** | **Destination filters**: port snake's `match` + `rulefile` with its test vectors; ASN/CIDR sets; answers → nft sets before the reply; `pyvpn rules check/test/import/export` | snake's match vectors pass; app + domain policies route only the matched destinations |
| **M6** | **Strict netns isolation**, `pyvpn install` (systemd unit), persistence, `--json` everywhere, desktop integration (`.desktop` launcher wrapper: "Open with pyvpn → policy") | **v0.1 public release** |
| **M7** | Later: local web UI / tray, `session:`/`if:` rules per app, SNI sniffing for apps with their own DoH, macOS (native helper), Windows (WinDivert) | — |

## 8. Testing

* **Unit (no root):** rule engine, config, nft ruleset *generation* (golden
  JSON), failover state machine with a fake clock, selector matching against
  fake `/proc` trees.
* **Integration (root, Linux CI on GitHub runners with sudo):** a pytest fixture
  builds namespaces: "host" ↔ veth WAN ↔ "internet" ns, plus a WireGuard peer ns
  as the tunnel exit and a fake DNS server in each. Tests launch processes
  through `pyvpn run` and assert which interface their traffic and DNS use.
  Needs cgroup v2 delegation inside the runner (supported on ubuntu-24.04).
* **Compatibility:** snake `.rules` files load and match the same way.

## 9. Risks

* **cgroup v2 required** (default on all current distros). cgroup v1 or hybrid
  systems: fall back to UID-based policies plus a warning.
* **Moving processes between cgroups** can conflict with systemd's own
  scopes. Prefer launching through `pyvpn run` / a transient systemd scope
  (`systemd-run --scope --slice=pyvpn-<id>.slice`); move running processes
  only for exe selectors, and document it.
* **Sockets opened before a move** keep their old route. Documented, plus
  `pyvpn apps --restart` hints.
* **Masquerade and source address**: needed for apps whose source address was
  picked for WAN. Covered by integration tests for TCP, UDP and QUIC.
* **Root daemon**: keep it small; CLI and UI unprivileged over the socket.

## 10. Open questions

1. Linux first, macOS/Windows later — OK? (Per-app routing on macOS needs a
   signed native Network Extension; it cannot be pure Python.)
2. Tunnels: managed WireGuard/OpenVPN **and** existing interfaces (proposed),
   or only one of them?
3. Should running processes be moved automatically by exe name (watcher), or
   only apps launched through `pyvpn run` / systemd units? The watcher is
   more convenient but more intrusive.
4. PyPI name: `snakevpn` (proposed), `policyvpn`, or another?
5. Keep snake's rule language for destination filters (proposed: yes)?
