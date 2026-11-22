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
   ├─ DNS (port 53) ──► nft redirect ─► per-policy stub on IPv4/IPv6 loopback
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
              ──► nft postrouting: verify egress, then masquerade to the interface's address
                    (the source address was chosen for the default route before re-routing)
```

Linux backend details (stream C, `netfilter/`, `routing/`,
`platform/linux/backend.py`):

* Chains: `dns` (nat, output, prio -100) redirects port 53 first, so a mark
  set later never hides an app's query; only packets whose *socket* already
  carries a pyvpn mark (the stubs' upstream sockets, `SO_MARK`) skip it.
  `output` (route, prio -90) exempts LAN/loopback/multicast, leaves
  socket-marked packets alone, enforces the current leak and routing rules
  of the policy recorded in conntrack, then classifies unmarked connections
  by their app and destination.
  `egress` (postrouting) checks marked packets against the actual outgoing
  interface for their policy and address family. It drops packets on a
  different interface and drops all marked packets for an unreachable
  family. `masq` masquerades mark P out of P's interface; `restore`
  (prerouting) copies the conntrack mark back onto replies.
* Marks are written as `mark & ~POLICY_MARK_MASK | P`, so bits other
  software uses survive. A kill-switch policy's traffic is rejected in nft
  *and* hits the unreachable table; it is never marked for another route.
* DoT and known-DoH rejects apply to every packet of the policy's apps (they
  bypass the stub); IPv6 and QUIC rejects apply to the traffic the policy
  governs (everything, or only its destination sets).
* The ruleset is built as nft JSON (golden-tested) and loaded as rendered
  nft script text in one `nft -f -` transaction (`add`/`delete`/`add table`):
  nft 1.0.9 (Ubuntu 24.04) cannot parse `socket cgroupv2` in JSON.
* Apply and teardown temporarily reject marked output in a separate nft
  table, update the policy routes and rules, then replace the classifier and
  remove the guard in one nft transaction. A failed update restores the
  previous routes and rules before lifting the guard, provided this daemon
  previously installed a plan successfully. If recovery fails or startup
  cannot install its first plan, the guard remains until a successful apply.
  A plan referring to a missing cgroup is rejected before changing rules.
  Each `nft` command has a deadline. The backend terminates a stalled
  command and waits briefly for it to exit. After a final-batch timeout, it
  reads the kernel's tables once the command has exited. The same atomic
  batch replaces the classifier and removes the guard, so a retained guard
  permits rollback and a verified commit keeps the new routes. If the
  outcome cannot be verified, the backend keeps the matching routes or the
  guard already in the kernel and recovers by reapplying under a fresh
  guard. It waits for the old command to exit before issuing further nft
  commands, and holds DNS destination updates until routing is recovered.
* `socket cgroupv2` rules hold the cgroup ID nft resolved at load time. If
  a policy cgroup or its parent slice is recreated, Linux placement
  reinstalls the last plan, including learned destinations, before moving
  the PID. The move writes into the exact installed cgroup, and a failed
  reinstall or a further cgroup replacement refuses placement. The backend
  also polls for cgroups recreated outside placement. A dedicated chain
  rejects unknown children of the installed `pyvpn.slice` before the LAN
  exemption. Domain-only policies register their placement cgroups while
  continuing to match all user processes. Exclusions by `exe`/`name` are
  deferred (§3.3); if they return, the app watcher will move processes into
  top-level exclusion cgroups, and the backend must recognize those
  installed cgroups in this check and track their IDs.
* Policies for every process (`any_process`) also require `meta skuid`, so
  kernel sockets are never marked: a WireGuard endpoint inside a
  destination set cannot loop the tunnel's own packets into it. A
  userspace VPN client is an ordinary process and still needs to stay out
  of the destination sets.
* `apply` turns on `net.ipv4.conf.all.src_valid_mark` (as `wg-quick` does)
  so strict `rp_filter` validates replies with their restored mark; it is
  left on at teardown. A kernel booted without IPv6 gets IPv4 rules and
  routes only.

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
| exclusions | `exclude_apps: [...]` | the same selectors; an excluded app never matches. `exe`/`name` are deferred for now (see below for policies without apps) |

Already-open sockets keep their route; new connections follow the new
cgroup (as in snake: "connections keep their route").

Exclusions on a policy with destination rules and no apps (an
`any_process` binding) exempt processes from that policy's marking. This
is how a userspace VPN client (OpenVPN, a provider app) whose server
address is in the policy's destination set keeps its encrypted packets on
the normal route instead of looping them into the target. Kernel tunnels
(WireGuard) need no exclusion: `any_process` matches only packets with a
socket owner (`meta skuid`), which kernel sockets lack. Exclusions travel
in `AppBinding.exclude_cgroup_paths` and `exclude_uids`, and the backend
skips a socket in one of those cgroups (or below it) or owned by one of
those uids:

- `unit`, `flatpak`, `snap`: their existing cgroup path; nothing is moved.
- `uid`, `user`: `exclude_uids`.
- `exe`, `name`: **deferred.** A destination-only binding grants no
  exemption for these selectors (the test fake records them in
  `unresolved`), because Linux keeps a process's cgroup across `exec`: a new
  program can open a socket before the watcher revokes the exemption, and
  that socket would then skip the policy. With `on_down: block` it would
  leave through the default route instead of being dropped, and rechecking
  on reload or restart does not close that window. Exemptions by
  `exe`/`name` can return once they can be revoked before a new executable
  opens a socket. The `pyvpn.slice/x-<hex>` names
  (`constants.excluded_cgroup` / `parse_excluded_cgroup`) and the backend's
  handling of them are reserved for that change; nothing creates such a
  cgroup today.

Only the test fake fills these fields today: the real app manager grants no
exemption on a destination-only binding for any selector kind. That is
fail-closed, but silent; reporting it in `pyvpn test` and `pyvpn audit` is a
follow-up.

An `any_process` binding may also list the policy's own cgroup
(`pyvpn.slice/p-<id>`) in `cgroup_paths`, so `pyvpn run` works for
destination-only policies; it never lists other cgroups or `uids`.

Two rules keep exclusions fail-closed:

- **Positive matches only.** The backend tests exclusions with positive
  matches (a socket in an excluded cgroup or owned by an excluded uid
  returns before the policy's rules) and every other socket continues
  through normal policy handling: target route, kill switch and DNS
  redirect. A negated `socket cgroupv2 level N != …` is not used, because it
  does not match a socket with no ancestor at depth N (for example one in a
  shallower cgroup), which would leave that socket ungoverned.
- **Revalidate on reload and restart.** When `x-<hex>` exclusions return,
  an `x-<hex>` name will be keyed by policy positions, not selectors, so it
  must survive a reload that changes the selectors. The app manager will
  then withhold every existing `x-*` path from `exclude_cgroup_paths` until
  it has checked each live member against the committed exclusions; members
  that no longer match return to their policy cgroup before the path is
  published again. Nothing creates `x-*` paths today. If one exists, the
  backend treats it as a known child of `pyvpn.slice` (or of `p-Q` when
  nested) for the stale-cgroup check and cgroup-id reapplication, so its
  members are governed rather than rejected. Listed exclusion cgroups
  (`unit`/`flatpak`/`snap` paths) must exist when a plan is applied.

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
destinations to every process except those its `exclude_apps` match
(§3.3). The per-policy DNS stub scopes the active
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

* Each policy gets its own UDP and TCP stub on `127.0.0.1:53<id>` and, when
  IPv6 loopback is available, `[::1]:53<id>`. nft redirects port 53 **from
  that policy's apps** to loopback in the query's address family, which
  also catches hard-coded resolvers. Both listeners use the same policy
  and upstream settings. The composition root supplies the Linux
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
  DNS.** If several destination-only policies match the same DNS query,
  the first matching policy with a stub serves it. Its upstream depends on
  that policy's target even when the matcher learns a destination for a
  later policy.
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
* **Integration (root, GitHub ubuntu-24.04 runners with sudo):** a pytest
  fixture builds namespaces: "host" with a veth "WAN" to an "internet" ns,
  and a second veth or WireGuard link that stands in for a VPN interface
  (the fixture creates it, pyvpn does not). Tests launch processes through
  `pyvpn run`, delete and re-create interfaces, and assert by capture which
  interface the traffic and DNS left through.
* **Linux backend integration (root on Linux):**
  `sudo .venv/bin/python -m pytest -m integration tests/platform/test_linux_namespace.py`
  applies real plans in a disposable namespace with dummy interfaces and
  one throwaway cgroup, and checks by nft counters that the cgroup's traffic
  leaves via the target, that nothing leaves after link loss or under the
  kill switch, DNS redirection to the stub, and that teardown leaves nothing.
  It also checks replies under strict `rp_filter`, a re-created cgroup, and
  a WireGuard handshake to an endpoint inside a destination set.
  Workers enter the namespace with `nsenter --net`, not `ip netns exec`,
  which remounts `/sys` and hides the cgroup tree.
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
* **Competing VPN rules** can win before a pyvpn policy lookup. The
  postrouting filter drops traffic that still carries a managed mark and
  would leave through another interface. An explicit fallback to the host
  route or an unmanaged address family is exempt from this check. Other
  VPN kill switches can still block traffic.
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
