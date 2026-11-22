# AGENTS.md

Instructions for coding agents (Claude Code, Codex, Copilot, etc.) working in
this repository.

## Project

pyvpn is **per-process policy routing** for the machine it runs on: it sends
each app's traffic (and its DNS) out through a chosen, already-existing
interface (`wg-jp`, `tun0`, `wlan1`, …), with fallback or a kill switch when
that interface is down. It does **not** create or manage VPN connections.

[PLAN.md](PLAN.md) is the source of truth for design, scope and milestones.
Read the relevant section before you change behaviour, and update PLAN.md in
the same change when a decision in it changes.

Key points from the plan:

- Distributed on PyPI as `snakevpn`; the import package and CLI are `pyvpn`.
- Python ≥ 3.11, `src/` layout, `pyproject.toml` with hatchling.
- **Linux only for now** (nft `socket cgroupv2` + fwmark + `ip rule`, via
  `pyroute2`). macOS, Windows and proxy mode are deferred; don't build them
  unless asked.
- Platform-specific code lives under `src/pyvpn/platform/linux/`, behind the
  `Backend` protocol in `platform/base.py`. The shared core (config, rule
  engine, DNS stubs, daemon, CLI) stays OS-agnostic so other OSes can be
  added later.
- The root daemon stays small. The CLI and `pyvpn run` run unprivileged and
  talk to the daemon over its unix socket.

This is a group project built in parallel. [WORKSTREAMS.md](WORKSTREAMS.md)
assigns each directory to a workstream. Stay inside your stream's
directories, code against the Phase 0 contracts (`state.py`,
`platform/base.py`, `daemon/api.py`, `config/models.py`, `constants.py`) and
the fakes in `tests/fakes/`, and do not change a contract without approval
from the streams that use it.

## Working rules

- **Fail closed.** Any change to routing, nft rules or DNS must not open a
  leak window. With `on_down: block`, traffic is dropped, never sent through
  the default route.
- **Never touch the host network in unit tests.** Unit tests are pure (golden
  nft JSON, fake netlink events, fake `/proc` trees). Anything that needs root
  belongs in the namespace-based integration tests (PLAN.md §8).
- Do not run commands that change the developer's live routing, nft ruleset
  or cgroups outside a throwaway network namespace.
- Keep changes scoped to the task; don't reformat unrelated code.

## Tooling

Once the M0 scaffold exists (see PLAN.md §7):

```bash
ruff check . && ruff format --check .
mypy src
pytest            # unit tests, no root
sudo .venv/bin/python -m pytest -m integration   # netns integration tests (Linux, root)
```

Run lint, types and unit tests before committing.

## Git and commits

- **Commit with the local git user account.** Use whatever `git config
  user.name` / `user.email` resolve to in this checkout. Do **not**:
  - set or change `user.name` / `user.email` (local or global config),
  - pass `--author`, or set `GIT_AUTHOR_*` / `GIT_COMMITTER_*` env vars,
  - commit as a bot or tool identity (e.g. `Claude <noreply@anthropic.com>`).

  A `Co-Authored-By:` trailer for the agent is fine; the author and committer
  must be the local user.
- Commit only when asked. Work on a branch, not directly on `main`.
- Write short, imperative commit subjects (e.g. `Plan: …`, `Add …`, `Fix …`).
- Never force-push or rewrite history that has been pushed without explicit
  approval.

## Branch names

Lowercase, words separated by `-`, no spaces. `<s>` is the workstream
letter from [WORKSTREAMS.md](WORKSTREAMS.md).

| Template | Use for | Example |
|---|---|---|
| `stream/<s>-<name>` | the one long-lived branch per workstream | `stream/b-daemon` |
| `feat/<s>-<topic>` | a new feature inside one workstream | `feat/d-gateway-discovery` |
| `fix/<s>-<topic>` | a bug fix inside one workstream | `fix/c-ipv6-masquerade` |
| `contracts/<topic>` | a change to a Phase 0 contract (needs approval from the streams that use it) | `contracts/destset-ports` |
| `ci/<topic>` | CI, tooling, release workflow | `ci/pin-ruff` |
| `docs/<topic>` | `PLAN.md`, `WORKSTREAMS.md`, `AGENTS.md`, README | `docs/branch-names` |

Long-lived stream branches:

| Stream | Branch |
|---|---|
| A config & CLI | `stream/a-cli` |
| B daemon | `stream/b-daemon` |
| C Linux routing & nft | `stream/c-routing` |
| D targets | `stream/d-targets` |
| E apps | `stream/e-apps` |
| F DNS & leaks | `stream/f-dns` |
| G rule engine | `stream/g-rules` |
| I test bed & CI | `stream/i-ci` |

- `feat/` and `fix/` branches start from their stream branch (or `main`)
  and merge back into it; `contracts/`, `ci/` and `docs/` merge into `main`.
- Agents: branches created automatically by a tool (e.g. `claude/<random>`)
  must be renamed to one of these templates before pushing.
- Delete a branch once it is merged; never delete another person's branch
  without asking.
