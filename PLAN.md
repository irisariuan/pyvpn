# pyvpn — plan

**App-based (process-based) policy routing** for the machine it runs on,
packaged for PyPI. It is the client-side counterpart of
[snake](https://github.com/irisariuan/snake): snake chooses a tunnel per
*device* on a router; pyvpn chooses an **outgoing interface per process** on
a Linux laptop or desktop. **macOS and Windows are deferred** (§2).

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
  sock_diag, process-event connector), `dnspython` (DNS message parsing and
  serialization), and `pydantic` v2 (config). The `snakevpn[doh]` extra
  installs `aiohttp` for DNS over HTTPS.
* Release: on a published `v*` GitHub Release, GitHub Actions runs the
  tests, builds sdist and wheel, uploads them to TestPyPI, checks that the
  files on TestPyPI have the same sha256 as that build, installs that
  version back from TestPyPI and runs `pyvpn --version`, and only then
  publishes the same files to PyPI, all with **Trusted Publishing** (no
  stored token). A manual run of the workflow (from `main` only) stops
  after the TestPyPI check. Publish runs never overlap.

## 2. Platforms: Linux, macOS, Windows

> **Decision (2026-11-20): Linux only for now.** macOS, Windows and proxy
> mode (§2.2 mode 3, M6, M8, M9) are deferred. §2.1–2.4 stay as reference
> for later. Keep the `platform/base.py` `Backend` protocol so another OS
> can be added without touching the core.

The shared core is pure Python on every OS: config, the rule engine, the
per-policy DNS stubs, target (interface) watching, the daemon and its API,
and the CLI. What differs is **how a packet is tied to a process and forced
out through an interface**. Only Linux can do that with what the OS ships
and from Python alone.

### 2.1 Summary

| | Linux | macOS | Windows |
|---|---|---|---|
| Per-app transparent routing | nft `socket cgroupv2` + fwmark + `ip rule`: **pure Python, in-kernel speed** | **Network Extension** (`NETransparentProxyProvider`) as a **signed Swift system extension**; flows are relayed in user space | **WFP bind/connect-redirect callout driver** (own driver needs EV signing), or **WinDivert** (signed third-party driver) packet rewriting |
| Per-user routing | nft `meta skuid` | pf `route-to … user <uid>`: pure Python | — (WFP user conditions only block or allow) |
| Per-app kill switch / leak blocks | nft | NE filter, or pf `user` rules (by user only) | **WFP filters with `ALE_APP_ID`**: user mode, ctypes, **no driver needed** |
| Per-app DNS | redirect port 53 per cgroup | hard: apps resolve through `mDNSResponder` | hard: apps resolve through the DNS Client service (`Dnscache`) |
| Interface events | netlink | `PF_ROUTE` socket / SystemConfiguration | `NotifyIpInterfaceChange` (IP Helper, ctypes) |
| Bind a socket to an interface (stubs, probes) | `SO_BINDTODEVICE` | `IP_BOUND_IF` / `IPV6_BOUND_IF` | `IP_UNICAST_IF` / bind to the interface address |
| Ships via pip alone? | yes | no: also a notarized `.app` / `.pkg` | no: also a signed driver / MSI |

### 2.2 Three routing modes

The `platform/` backend reports which modes it can do. Policies choose one,
or `auto` picks the best available mode:

1. **`transparent`**: every socket of the app, TCP and UDP, with no app
   cooperation. Linux natively; macOS with the native helper; Windows with
   the native helper.
2. **`user`**: everything a given OS user runs. Linux and macOS (pf),
   pure Python. Useful for daemons and CLI tools started as a dedicated user.
3. **`proxy`**: pyvpn runs a local SOCKS5 / HTTP CONNECT proxy per policy
   whose outgoing sockets are bound to the target interface (`IP_BOUND_IF`,
   `IP_UNICAST_IF`, `SO_BINDTODEVICE`). `pyvpn run` starts the app with the
   proxy configured (env vars; `--proxy-server` for Chromium-based apps; a
   pyvpn-managed Firefox profile). DNS is resolved by the proxy (SOCKS5
   remote DNS) through the target. **Pure Python on all three OSes, no
   signing**, but only for apps that honour proxies. UDP (QUIC, WebRTC)
   is not proxied, so it is blocked for that app where the OS allows
   (Windows WFP filter, macOS NE filter / pf by user) to force a TCP
   fallback.

**v0.x ships `transparent` (and `user`) on Linux only.** Proxy mode and
the macOS / Windows native helpers are deferred; if picked up later, the
helpers ship as separate signed downloads that the Python daemon detects and
drives.

### 2.3 macOS: difficulties

* **No in-kernel per-process routing that third parties can use.** pf
  matches `user`/`group` but not process or app. The only supported
  per-app hook is a Network Extension:
  * `NETransparentProxyProvider` (macOS 11+) receives every new TCP/UDP flow
    with the app's signing identifier and audit token. The provider opens
    the outgoing connection itself with `NWParameters.requiredInterface` =
    the target `utun`/`en` interface, then **relays the bytes in user
    space**. It is not packet routing, so throughput and latency cost more
    than on Linux. That is acceptable for browsers, but it shows at gigabit
    speeds.
  * `NEFilterDataProvider` can only allow or drop: useful for the kill
    switch, not for rerouting.
* **It cannot be Python.** A system extension is a Swift/Obj-C bundle
  inside an `.app` that must be installed in `/Applications`, signed with a
  **Developer ID** (Apple Developer Program, US$99/year) with the
  `app-proxy-provider-systemextension` entitlement, **notarized**, and
  **approved by the user** in System Settings (on managed Macs, via MDM).
  pip cannot install it. Plan: `native/macos/` Swift project built and
  notarized in CI on macOS runners, shipped as a `.pkg`. The Python daemon
  talks to it over a unix socket / XPC with JSON messages ("app bundle id X
  → interface utun4").
* **DNS per app**: most apps resolve through the system's `mDNSResponder`,
  so the transparent proxy sees DNS flows as coming from `mDNSResponder`,
  not from the app. Per-domain resolver files (`/etc/resolver/<domain>`) are
  global, not per app. Options: route all policy DNS by domain (snake's
  approach) instead of per app, or make the app's own DNS go through the
  proxy (browsers' DoH / SOCKS remote DNS). This needs a prototype.
* **Coexistence with VPN apps**: they are Network Extensions too (packet
  tunnels). Some set `includeAllNetworks` / enforce routes, which overrides
  `requiredInterface` connections that leave elsewhere. Behaviour differs
  per VPN app and must be tested per provider.
* **pf quirks for `user` mode**: `route-to` on outbound rules needs a NAT
  rule for the source address, pf must be enabled with our own anchor
  (`com.apple/pyvpn` would collide with Apple's; use a top-level anchor
  loaded via `pfctl -a pyvpn`), and macOS updates sometimes reset
  `/etc/pf.conf`.
* **SIP / hardened runtime** stop library injection (`DYLD_INSERT_LIBRARIES`
  to force `IP_BOUND_IF`) for most signed apps, so it is not an option.

### 2.4 Windows: difficulties

* **No per-process routing table.** Routing is global. What decides the
  interface for an app is its **source address**: Windows uses the strong
  host model, so a socket bound to the VPN interface's IP leaves through that
  interface. Per-app routing means **forcing other processes' sockets to
  bind to that IP**. That requires the kernel:
  * **WFP callout driver** at `FWPM_LAYER_ALE_BIND_REDIRECT_V4/V6` and
    `ALE_CONNECT_REDIRECT_V4/V6`: rewrites the bind/connect of chosen app
    IDs to the target interface address. This is how commercial VPNs' split
    tunnelling works (Mullvad's open-source `win-split-tunnel` is a
    reference design). Costs: a C kernel driver, an **EV code-signing
    certificate** (~US$300–600/year) plus **Microsoft attestation
    signing** through Partner Center; it must be HVCI/Memory Integrity
    compatible; a bug blue-screens the machine.
  * **WinDivert** (signed open-source driver, usable from Python via
    `pydivert`): its FLOW/SOCKET layers report the process ID of each flow,
    and its NETWORK layer lets you rewrite and reinject packets. Per-app
    routing then means **user-space NAT**: rewrite the source to the target
    address, reinject toward the target interface, translate the replies
    back. No own driver signing is needed. But every packet of a routed
    app passes through user space (too slow in Python, so write it as a
    small Rust/C helper), some anti-cheat and antivirus software flags
    WinDivert, and edge cases (fragmentation, IPv6, offloads) make it
    fiddly.
  * **Recommendation:** WinDivert helper first (no certificate), own WFP
    driver later if the project grows.
* **Kill switch and leak blocks are easy**: WFP *filters* (no callout) with
  `FWPM_CONDITION_ALE_APP_ID` and `IP_LOCAL_INTERFACE` conditions are added
  from user mode through `fwpuclnt.dll` (ctypes). Use a dynamic session or a
  persistent sublayer so the filters are removed, or kept on purpose, if the
  daemon dies.
* **DNS per app**: apps call the DNS Client service, which resolves on
  their behalf (as `svchost`), so the app identity is lost. NRPT rules are
  per domain, not per app. The same options as on macOS apply (per-domain
  routing, or proxy-mode DNS); this needs a prototype.
* **Service and installer**: the daemon runs as a Windows service
  (`pywin32`), the CLI talks to it over a named pipe with an ACL, and the
  driver/helper is installed by an MSI as admin. None of this comes from
  `pip install`.
* **Interface identity**: VPN adapters (Wintun, TAP, provider-specific) are
  matched by alias or GUID, not by `tun0`-style names. Their addresses
  change on reconnect, so redirects must follow `NotifyIpInterfaceChange`.

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
                                   + higher-metric unreachable default (link-loss guard)
                                 | unreachable default               (kill switch)
                                 | no policy lookup for that mark    (fall back to host routing)
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
* `gateway: "auto"` requires a discovered next hop for the target to be usable;
  when absent, pyvpn can fall back to another target. A target reports one next
  hop (IPv4 preferred); separate IPv4 and IPv6 gateways need a contract change.
  With no configured gateway, point-to-point targets use device-only routes.
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

Policy names are unique. Reload, and a daemon restart, keep each policy
that has used an app cgroup at the same position in the config (the
reserved positions are saved in the daemon's state file, since rules and
cgroups outlive the daemon). A state file that exists but cannot be read
stops the daemon from starting rather than losing those reservations.
DNS-learned destinations are saved there too and restored before the
first apply, so a restart keeps governing addresses that apps have cached
(for policies whose name and domain rules are unchanged or only extended).
The daemon also refuses configs it cannot enforce: destination rules
without a rule matcher, `dns_via_target` without a DNS service, hostname
rules without `dns_via_target` (only the policy's DNS stub can learn their
addresses), and, on reload, changed target definitions (the target
watcher is set up at start).
Existing cgroups can still contain running apps after an app selector is
changed or removed, so reload rejects changes that would remove or reuse
those positions. Reload can still update policy settings, append policies,
and edit domain-only policies that have never used an app cgroup when
those changes preserve the reserved positions. The daemon saves new
reservations before applying a routing plan or moving a process.

### 3.4 Destination filters (optional, from snake)

A policy with only apps sends **all** of their traffic through the target. A
policy with apps **and** destination rules sends only the matched
destinations (snake's domain rules, `asn:`, `cidr:`) through it. A policy
with destination rules and no app selectors or exclusions applies those
destinations to every process. The per-policy DNS stub scopes the active
rule matcher to its own policy and those global policies before matching the
query name and its CNAME chain. A and AAAA answers, HTTPS/SVCB address hints,
and additional addresses for referenced names go into the winning policy's
nft sets *before* the reply is released. For HTTPS and SVCB, the stub follows
alias records included in the response to collect the endpoint addresses and
hints. Before releasing a cacheable alias, the stub records its name path,
DNS class, listener policy ID, and expiry in the daemon's private
`dns-aliases.sqlite3` state file. Tracking follows the records in the reply. This includes SRV, MX and NS
targets (including nameservers in a referral), plus CNAMEs returned for other query types or alongside NXDOMAIN.
The stub narrows DNAME redirects to the verified, host-specific synthesized
CNAME before replying, so sibling names must go through policy matching.
It returns SERVFAIL when the subtree record itself or DNSSEC proof is
requested, or when the redirect has no verifiable CNAME in the answer chain.
Bundled endpoint addresses and separate A/AAAA lookups use the same policy.
Follow-up queries, including those received after a restart, match the
remembered prefix and the new answer together against the active rules.
For a shared endpoint, a single matching policy governs the address even
when other cached paths have no match. A direct match also participates. Each hop bounds the
path's TTL. Alias deadlines use the system monotonic clock across daemon restarts.
If uptime resets below the last saved clock reading, the stub preserves the TTL
remaining at that reading. After the durable write, the stub caps each returned alias link's
TTL at the whole seconds still covered and withholds an expired link.
If indistinguishable live paths select
different policies, or publication or alias storage fails, the stub returns
SERVFAIL. A shared lock serializes publication and alias storage across stubs,
so a slow update can consume another query’s five-second timeout.
The daemon composition root supplies the active rule
matcher to all stubs, including app-only stubs.

Rule semantics (`match/policy.py`): policies are tried in config order and
the first whose rules route a name wins; `!rule` exempts a name from that
policy only. `drop:` rules parse but are not enforced yet (that needs a
drop set in the backend contract), so the daemon refuses to load a config
that has them. It also refuses snake's per-device rules (they would hide
plain rules in the same policy), rules that do not parse and `asn:` entries
with no cached prefixes; `pyvpn rules check` reports all of these as
errors, and `pyvpn rules test` names a policy whose per-device rule hid a
name. Rule regexes and wildcards use RE2 syntax (constructs RE2 lacks or
reads differently, such as `\Z`, `(?x)` or `a{,3}`, are rejected with either
engine) and are matched in linear time by the optional `google-re2` package
(`snakevpn[re2]`). It stays optional, but without it the daemon refuses to
activate regex rules and wildcards with more than one `**` or more than one
`*` in a label, since Python's backtracking `re` could stall the DNS path on
a crafted name; simple wildcards (`*.example.com`, `**.cdn-*.example.net`)
still work. `pyvpn rules check` parses such rules and warns. snake's
per-device rules (`session:`, `route:`, `drop[...]:`, `if:` branches) parse
but route nothing; only the names in an `if:` condition are routed, as in
snake. snake's Domain VPN Routing importer is not ported (router-only).

### 3.5 Per-app DNS and leaks

* Each policy gets its own stub (`127.0.0.1:53<id>`). nft redirects port 53
  **from that policy's apps** to it, which also catches hard-coded `8.8.8.8`.
  The stub listens on UDP and TCP. The composition root supplies the Linux
  socket factory, which binds upstream sockets to the target interface and
  sets the policy's mark before connecting so the policy's route and gateway
  apply. With no `dns_server`, the stub uses Quad9 at
  `9.9.9.9` on that interface. Set a numeric address to override it.
  DoT and DoH accept `hostname@address` to verify the TLS certificate
  without consulting the system resolver. Encrypted requests to the
  default upstream verify `dns.quad9.net`. DoH sends POST requests to
  `/dns-query`, requests uncompressed responses, and reuses HTTPS
  connections per policy. The stub returns
  SERVFAIL if the target or DNS upstream is unavailable, including during
  routing fallback to the host default route. The daemon's bound upstream sockets
  must be exempt from port-53 redirection so queries cannot loop into a stub.
* Reload stops the existing policy DNS listeners before applying the new
  routes. The daemon activates the new matcher before reopening listeners,
  so an answer cannot use the previous config's matching rules.
* Other apps keep the system resolver. **pyvpn does not take over system
  DNS.**
* Per-policy leak toggles (snake's): block DoT 853, block known DoH
  addresses, block QUIC, IPv6 `route`/`block`/`off`. A stub with
  `block_doh` answers Firefox's `use-application-dns.net` canary with NXDOMAIN.
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
  proxy/        (deferred) per-policy SOCKS5 / HTTP CONNECT proxy with interface-bound upstream sockets
  platform/     base protocol + capability flags; linux/
                (deferred: darwin/ pf, PF_ROUTE, helper client; windows/ IP Helper + WFP)
native/         (deferred)
  macos/        Swift system extension (transparent proxy + filter), built/notarized in CI
  windows/      WinDivert-based helper (Rust/C), later a WFP callout driver
```

The root daemon owns nft, routes and cgroups. The CLI and `pyvpn run` are
unprivileged: `run` asks the daemon over the unix socket to place its own
PID in the policy's cgroup, then `exec`s the command, so the user's
environment and desktop session are kept.

The daemon runs as `pyvpn-daemon` (`src/pyvpn/daemon/main.py`, the composition
root). It wires the real parts of every stream: the netlink target watcher,
the cgroup app manager and process watcher, the DNS stubs with bound
upstream sockets, and the rule matcher with its ASN cache. It loads the
backend from `pyvpn.platform.linux.backend.LinuxBackend`. If that module is
missing, the daemon refuses to start (fail closed). `--backend dry-run` logs
each routing plan instead of installing it, for development without root.
It routes nothing, keeps cgroups in a scratch directory and turns off the
process watcher, and it is never the default.

The daemon locks its socket's companion lock file before changing routing
and holds the lock through shutdown. It binds the API socket during startup
and begins serving requests after the initial install attempt.

`pyvpn disable` removes every rule and stub and stays in effect, across
daemon restarts (the enabled flag is in the daemon's state file), until the
API's `enable` call. `reload` while disabled loads and binds the new config
but installs nothing; it never re-enables routing on its own. While
disabled, `place_pid` returns `unavailable` and `status` reports each
policy as `not_installed`.

## 7. Milestones

| # | Milestone | Done when |
|---|---|---|
| **M0** | Scaffold: pyproject, ruff, mypy, pytest, CI (3.11–3.14), Trusted Publishing workflow | `pip install snakevpn` from TestPyPI prints a version |
| **M1** | **Core app routing**: daemon + unix socket, cgroup manager, `pyvpn run -p P -- cmd`, nft output chain with `socket cgroupv2` marks, per-policy table + `ip rule`, masquerade, LAN exemption, kill switch, clean teardown, `pyvpn disable` | in a netns test bed, `pyvpn run -p X -- curl` leaves via the target and plain `curl` via the default route; with the target down and `on_down: block`, nothing leaks |
| **M2** | **Targets**: netlink watcher, interface patterns, gateway discovery for broadcast interfaces, ordered fallback, optional TCP probes / exit country | deleting and re-creating `tun0` switches the policy and switches back within 100 ms, with no leak in between |
| **M3** | **Selectors + watcher**: exe/name/unit/uid/flatpak, proc-connector watcher, app groups, exclusions, `pyvpn apps` | a normally started `/usr/bin/foo` lands in its policy within 50 ms, and its children follow |
| **M4** | **Per-app DNS + leak protection**: per-policy stubs, port-53 redirect per cgroup, resolver bound to the target, DoH/DoT/QUIC blocks, canaries, IPv6 modes, `pyvpn audit` | DNS leak tests: a routed app's queries only leave through its target |
| **M5** | **Destination filters**: port snake `match` + `rulefile` with its test vectors, ASN/CIDR sets, `pyvpn rules check/test/import/export` | snake's vectors pass; app + domain policies route only the matched destinations |
| **M6** | *(deferred)* **Proxy mode on all OSes**: per-policy SOCKS5/HTTP proxy bound to the target, `pyvpn run` launchers for Chromium/Firefox/env-proxy apps, target watching on macOS (`PF_ROUTE`) and Windows (IP Helper), Windows WFP per-app UDP/leak filters, CI on macOS + Windows runners | a browser launched by `pyvpn run` on all three OSes exits via the target |
| **M7** | Strict netns isolation, `pyvpn install` (systemd), `.desktop` helper, `--json` output | **v0.1 public release** (Linux) |
| **M8** | *(deferred)* **macOS native helper**: Swift `NETransparentProxyProvider` + filter in `native/macos/`, signed + notarized `.pkg` from CI, daemon ↔ helper protocol, macOS `user` mode via pf | transparent per-app routing on macOS 13–15 |
| **M9** | *(deferred)* **Windows native helper**: WinDivert-based per-app NAT helper (Rust/C) in `native/windows/`, MSI; later an own WFP bind-redirect driver | transparent per-app routing on Windows 10/11 |
| **M10** | Later: web UI / tray, `session:`/`if:` per app, SNI sniffing | — |

## 8. Testing

* **Unit (no root):** nft ruleset generation (golden JSON), route/rule plans,
  target selection with fake netlink events, selector matching against fake
  `/proc` trees, rule engine (snake's vectors), config migrations.
* **Network test bed (root on Linux):** `tests/conftest.py` provides the
  `netbed` fixture (stream I): a "host" namespace with a veth WAN to an
  "internet" namespace, a second veth standing in for a VPN interface, and
  one service address reachable over either link, so a source address
  identifies the egress interface. The fixture creates every part of it and
  removes both namespaces on teardown; nothing outside them is touched.
  Tests launch processes inside "host" with `netbed.run`, take links down and
  up with `netbed.down("vpn")` / `netbed.up("vpn")`, and read the egress
  interface from `netbed.tcp_echo()`, `netbed.udp_echo()` and
  `netbed.dns_query()`: the internet-side services started by
  `netbed.services()` reply with the source address they observed.
  Run the root suite with `sudo pytest -m integration`; CI runs the same
  command on every pull request in the `integration` job (ubuntu-24.04,
  Python 3.12), which remounts cgroups v2 read-write and runs
  `tests.ci.preflight` first: one clear message instead of test errors when
  the runner has no cgroup v2, no writable cgroup tree, no root or no `ip`/
  `nft`/`sysctl`. The unit suite stays root-free because the marker is
  deselected by default.
* **Standalone DNS integration (root on Linux):**
  `sudo .venv/bin/python -m pytest -m integration tests/dns/test_namespace.py`
  exercises the stubs with two DNS peers in disposable namespaces. It checks
  target-only queries and SERVFAIL after target deletion, using fake rule
  matching and destination-set updates.

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
* **Interface flaps**: the device route can disappear before the daemon sees
  the link event. Keep a higher-metric, device-independent `unreachable`
  default in each active policy table so the kernel stops there even if the
  device route vanishes. A policy with `on_down: default` returns to the host's
  normal routing only after reconciliation explicitly selects that fallback.
* **Root daemon**: keep it small; everything else runs unprivileged.

## 10. Open questions

1. ~~Cross-platform order~~ — decided 2026-11-20: Linux only for now;
   macOS, Windows and proxy mode deferred.
2. Should running processes be moved automatically by exe name (watcher), or
   only apps launched through `pyvpn run` / systemd units?
3. Should a policy have several targets with fallback, or exactly one
   interface (simpler)?
4. PyPI name: `snakevpn` (proposed), `policyvpn`, or another?
5. Keep snake's domain-rule language for optional destination filters?
