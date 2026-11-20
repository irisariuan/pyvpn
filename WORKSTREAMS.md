# pyvpn — parallel workstreams

How to split [PLAN.md](PLAN.md) so that several people can build it at the
same time and merge it at the end with few conflicts.

The idea: **agree on a small set of shared contracts first (Phase 0), then
every workstream owns its own directory and codes only against those
contracts and fakes.** Nobody waits for another stream's real code; a stream
tests itself with fakes of the others. The daemon (stream B) is where
everything is plugged together.

```
                    ┌──────────── Phase 0: contracts (everyone reviews) ────────────┐
                    │ config models · state types · Backend protocol · API schema │
                    │ constants · fakes                                           │
                    └───────────────────────────────┬─────────────────────────────┘
        ┌──────────┬──────────┬──────────┬──────────┼──────────┬──────────┬──────────┐
        A          B          C          D          E          F          G          H
     config     daemon     routing   targets     apps       DNS      rule engine  proxy +
     + CLI      (hub)      + nft                          + leaks    (snake port) other OS
        └──────────┴──────────┴──────────┴────┬─────┴──────────┴──────────┴──────────┘
                                              I: test bed, CI, release (supports all)
                                              │
                                    Phase 2: integration (B wires real parts)
```

---

## Phase 0 — shared contracts (do first, together, ~1 week)

One person drives, **everyone reviews**, merge to `main` before anyone starts
a stream. After this, changing a contract needs a PR approved by the owners of
every stream that uses it.

| File | Contents |
|---|---|
| `pyproject.toml`, ruff, mypy, pytest config, CI skeleton | M0 scaffold so every stream runs the same checks |
| `src/pyvpn/constants.py` | fwmark range, table ids (`1000+id`), `ip rule` prefs (`5200+id`), cgroup root `pyvpn.slice`, stub port base `53<id>`, nft table name, socket path |
| `src/pyvpn/config/models.py` | pydantic models for PLAN.md §5: `Target`, `AppSelector`, `AppGroup`, `Policy`, `LeakSettings`, `Settings`, `Config` (fields only; validation details can follow) |
| `src/pyvpn/state.py` | runtime data passed **between** streams (frozen dataclasses, see below) |
| `src/pyvpn/platform/base.py` | `Backend` protocol + `Capabilities` flags |
| `src/pyvpn/daemon/api.py` | daemon API: JSON-lines over the unix socket, method names, request/response dataclasses |
| `tests/fakes/` | a fake for every interface below, so streams test without each other |

### The data that flows between streams (`state.py`)

```python
@dataclass(frozen=True)
class TargetStatus:          # produced by D (targets)
    name: str                # config target name
    interface: str | None    # resolved interface (patterns resolved), None if absent
    ifindex: int | None
    usable: bool             # link up + address [+ probe ok]
    gateway: IPAddress | None
    addresses: tuple[IPAddress, ...]

@dataclass(frozen=True)
class AppBinding:            # produced by E (apps)
    policy_id: int
    cgroup_paths: tuple[str, ...]   # e.g. "pyvpn.slice/p-3", "app-flatpak-…scope"
    uids: tuple[int, ...]

@dataclass(frozen=True)
class DestSet:               # produced by F (DNS answers) and G (asn:/cidr:)
    policy_id: int
    v4: frozenset[IPv4Network]
    v6: frozenset[IPv6Network]

@dataclass(frozen=True)
class PolicyPlan:            # computed by B, consumed by C / platform backends
    policy_id: int
    mark: int
    table: int
    route: Literal["dev", "unreachable", "main"]
    interface: str | None
    gateway: IPAddress | None
    apps: AppBinding
    dests: DestSet | None    # None = all destinations
    leak: LeakSettings
    dns_stub_port: int | None

@dataclass(frozen=True)
class RoutingPlan:           # the whole desired state, applied atomically
    policies: tuple[PolicyPlan, ...]
```

### The interfaces (all `async`, all have fakes in `tests/fakes/`)

| Interface | Owner | Used by | Shape |
|---|---|---|---|
| `TargetWatcher` | D | B | `async def statuses() -> AsyncIterator[dict[str, TargetStatus]]` |
| `AppManager` | E | B | `async def bind(policy, selectors) -> AppBinding`, `async def place_pid(pid, policy_id)`, `async def bindings() -> AsyncIterator[...]` |
| `DnsService` | F | B | `async def start(plan)`, `async def stop(policy_id)`, `def on_answer(cb: Callable[[DestSet], Awaitable[None]])` |
| `Backend` (platform) | C (Linux) / H (others) | B | `capabilities`, `async def apply(plan: RoutingPlan)`, `async def add_to_set(DestSet)`, `async def teardown()` |
| `RuleMatcher` | G | F, B | `def match(domain: str) -> int | None` (policy id), `def static_sets() -> list[DestSet]` |
| Daemon API | B | A, E (`pyvpn run`) | methods: `status`, `apps`, `reload`, `place_pid`, `disable`, `audit` |

---

## Phase 1 — workstreams (in parallel)

Each stream owns the listed directories. **Do not edit another stream's
directories**; if you need a change there, open an issue or ask the owner.
Each stream's "done" is tested **with fakes only** — no other stream's real
code needed.

### A — Config & CLI
- **Owns:** `src/pyvpn/config/` (except the Phase 0 field list, which becomes yours to extend), `src/pyvpn/cli/`, `src/pyvpn/daemon/client.py`
- **Builds:** full validation and error messages, config migrations, `pyvpn status / apps / policy / test / disable / install` (talking to the daemon API), `--json` output, `.desktop` helper.
- **Tests against:** a fake daemon socket server that returns canned responses.
- **Done when:** every CLI command works end-to-end against the fake daemon; invalid configs give clear errors.
- **Skills:** Python, CLI design. Good first stream for someone new to networking.

### B — Daemon core (integration hub)
- **Owns:** `src/pyvpn/daemon/` (except `client.py`)
- **Builds:** asyncio event loop, unix-socket API server, persistent state, and the **reconcile loop**: config + `TargetStatus` + `AppBinding` + `DestSet` → `RoutingPlan` → `Backend.apply()`. Fallback order and `on_down` logic live here.
- **Tests against:** fakes of D, E, F, G and the backend; assert the exact `RoutingPlan` produced for scripted event sequences (target goes down, comes back, app starts…).
- **Done when:** scripted scenarios produce the right plans, including fail-closed behaviour during flaps.
- **Note:** B is also the one who swaps fakes for real parts in Phase 2, so B should be the person most comfortable with the whole design.

### C — Linux routing & netfilter
- **Owns:** `src/pyvpn/netfilter/`, `src/pyvpn/routing/`, `src/pyvpn/platform/linux/backend.py`
- **Builds:** pure nft ruleset builder `RoutingPlan → nft JSON` (output chain, `socket cgroupv2`, marks, ct mark save/restore, LAN exemption, masquerade, leak rejects, port-53 redirect), atomic apply via `nft -j -f -`, policy tables + `ip rule` via pyroute2, clean teardown.
- **Tests against:** golden JSON files (no root); a root netns test from stream I for apply/teardown.
- **Done when:** golden tests cover every `PolicyPlan` variant; apply + teardown in a netns leaves no rules behind.

### D — Targets
- **Owns:** `src/pyvpn/targets/`, `src/pyvpn/platform/linux/netlink.py`
- **Builds:** interface name/pattern resolution, netlink watcher (link/address/route), gateway discovery for broadcast interfaces, optional TCP probes bound with `SO_BINDTODEVICE`, optional exit-country check.
- **Tests against:** fake netlink event streams (no root); a netns test that deletes and re-creates an interface.
- **Done when:** M2's criterion is met in isolation — status changes are emitted within 100 ms of the netlink event.

### E — Apps
- **Owns:** `src/pyvpn/apps/`
- **Builds:** cgroup v2 manager (`pyvpn.slice/p-<id>`), selectors (exe / name / unit / uid / flatpak / snap / exclusions / groups), proc-connector process watcher with startup `/proc` scan, `pyvpn run` launcher (asks the daemon to place its PID, then `exec`), netns launcher for `isolation: netns`.
- **Tests against:** fake `/proc` trees and a temp cgroup directory; fake daemon for `pyvpn run`.
- **Done when:** M3's criterion is met — a started process lands in the right cgroup within 50 ms and its children follow.

### F — DNS & leak protection
- **Owns:** `src/pyvpn/dns/`, `src/pyvpn/audit/`
- **Builds:** per-policy stub resolvers, upstreams (plain / DoT / DoH) on sockets bound to the target, SERVFAIL instead of fallback, "fill dest sets before replying", DoH canary, `pyvpn audit` checks.
- **Tests against:** a fake `Backend.add_to_set`, a fake `RuleMatcher`, a local test DNS server.
- **Done when:** stubs answer correctly, push `DestSet`s before replying, and never send a query out of the wrong socket.

### G — Rule engine (port from snake)
- **Owns:** `src/pyvpn/match/`, `src/pyvpn/rulefile/`, `tests/vectors/`
- **Builds:** port of snake's `match` language and `.rules` format, AdGuard / hosts / dnsmasq converters, ASN / CIDR sets, `pyvpn rules check/test/import/export` command bodies (A wires them into the CLI).
- **Tests against:** snake's test vectors. **Fully independent — can start on day one, even before Phase 0 is merged.**
- **Done when:** all of snake's vectors pass.

### H — Proxy mode & macOS / Windows (pure Python parts)
- **Owns:** `src/pyvpn/proxy/`, `src/pyvpn/platform/darwin/`, `src/pyvpn/platform/windows/`
- **Builds:** per-policy SOCKS5 / HTTP CONNECT proxy with interface-bound upstream sockets (`IP_BOUND_IF`, `IP_UNICAST_IF`, `SO_BINDTODEVICE`), launchers for Chromium / Firefox / env-proxy apps, `TargetWatcher` for macOS (`PF_ROUTE`) and Windows (IP Helper), Windows WFP per-app block filters via ctypes.
- **Tests against:** local test servers; CI on macOS and Windows runners.
- **Done when:** M6's criterion — a browser launched via `pyvpn run` exits through the target on all three OSes.
- **Skills:** needs someone with a Mac and/or Windows machine.

### I — Test bed, CI, release
- **Owns:** `tests/integration/`, `tests/conftest.py` netns fixtures, `.github/workflows/`
- **Builds:** pytest fixture that builds the namespace test bed from PLAN.md §8 ("host", "internet", veth WAN, fake VPN link), capture helpers ("which interface did this packet leave through?"), CI matrix (3.11–3.13, Linux root job, macOS, Windows), Trusted Publishing release workflow.
- **Done when:** other streams can write `def test_x(netbed): ...` and get a clean namespace setup with assertions on egress.
- **Note:** small stream; whoever takes it can also take A or G.

### Later / optional (separate repos-in-repo, fully independent)
- **macOS native helper** (`native/macos/`, Swift, M8) — needs an Apple Developer ID.
- **Windows native helper** (`native/windows/`, Rust/C + WinDivert, M9).

These only depend on the daemon ↔ helper JSON protocol, which H defines.

---

## Assigning people

### How demanding each stream is

| Load | Streams | Why |
|---|---|---|
| **Hardest** | B daemon, C Linux routing & nft | B: concurrent events, fail-closed during flaps, owns integration. C: cgroup marks, ct marks, `ip rule`, masquerade, IPv6, competing VPN rules; leaks only show in root netns tests. |
| **Hard** | F DNS & leaks, E apps | F: bound DoT/DoH upstreams, fill sets before replying, leaks are privacy bugs. E: cgroup v2, proc connector races (children fork before the move), systemd scopes. |
| **Medium** | H proxy + other OS, D targets | H: WFP via ctypes, three OSes, needs a Mac/Windows machine. D: netlink events, gateway discovery, 100 ms target. |
| **Lighter** | G rule engine, A config & CLI, I test bed & CI | G: large but fully specified by snake's vectors. A: pure Python. I: small; the netns fixture is the only tricky part. |

Rules: put the strongest networking people on **B** and **C**, never give
both to one person, and give nobody more than one hard stream on top of a
hardest one.

### Suggested splits

Merge streams when the group is small:

| Group size | Person 1 | Person 2 | Person 3 | Person 4 | Person 5 |
|---|---|---|---|---|---|
| **3** | B + A + I | C + D | E + F | | |
| **4** | B + I | C + D | E + F | A + G + H | |
| **5** | B + I | C + D | E + F | A + G | H |
| **6+** | one stream each; the extra people take the native helpers | | | | |

**G is a floater** in the 3-person split: it depends on nothing, so whoever
finishes their streams first takes it (or it is shared). H in the 3-person
split starts after v0.1 Linux work is stable, or goes to whoever owns a Mac
or Windows machine.

Pairings keep each person's streams in neighbouring code (C + D are both
netlink/pyroute2; E + F both act per app at runtime; A + G are both mostly
pure Python; B + A + I all sit around the daemon API and tests).

---

## Branches and merging

- One long-lived branch per stream: `stream/a-cli`, `stream/b-daemon`, …
  Phase 0 goes to `main` first; every stream branches from it.
- **Merge into `main` early and often** (each time a stream's unit tests
  pass), rather than once at the end. Because streams own separate
  directories, these merges almost never conflict, and the final integration
  is much smaller. If the group prefers a single merge at the end, the
  directory ownership still keeps conflicts limited to `pyproject.toml` and
  the contracts.
- Shared files that everyone may touch: `pyproject.toml` (dependencies —
  add lines, don't reorder), `README.md`, `PLAN.md`. Contract files under
  Phase 0 need approval from every affected stream.
- Optional: a `CODEOWNERS` file mapping each directory to its stream owner,
  so GitHub requests the right reviewer automatically.

## Phase 2 — integration

Owned by B, with each stream owner on call for their part:

1. Replace fakes with real implementations one at a time, in this order:
   C (backend) → E (apps, `pyvpn run`) → D (targets) → F (DNS) → G (rules).
   After each swap, run the netns integration suite from I.
2. M1 end-to-end: `pyvpn run -p X -- curl` leaves via the target, plain
   `curl` via the default route, and nothing leaks with `on_down: block`.
3. Then M2–M5 criteria end-to-end, then H's proxy mode, then M7 release.

## Milestone → stream map

| Milestone (PLAN.md §7) | Streams |
|---|---|
| M0 scaffold | Phase 0 + I |
| M1 core app routing | B, C, E (`run` launcher), I |
| M2 targets | D, B |
| M3 selectors + watcher | E, A (`pyvpn apps`) |
| M4 DNS + leaks | F, C (redirect + leak rules) |
| M5 destination filters | G, F, A |
| M6 proxy mode | H |
| M7 release | A (`install`, `--json`), E (netns), I (release) |
| M8 / M9 native helpers | later, separate owners |
