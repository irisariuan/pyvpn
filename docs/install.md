---
title: Installing pyvpn
description: Install pyvpn (snakevpn) on Linux, check the requirements, set up the root daemon with systemd, and uninstall it cleanly.
license: GPL-3.0-or-later
---

# Installing pyvpn

This guide takes you from nothing to a running `pyvpn-daemon`. When you're
done, continue with the [usage guide](usage.md) to write your first policy.

> **Alpha software.** pyvpn routes traffic and enforces kill switches, and the
> routing is tested end to end in network namespaces, but it has seen little
> real-world use and hasn't been audited. Check what it does with
> `pyvpn audit`, and don't rely on it alone for privacy yet.

## 1. Check the requirements

| Requirement | Check | Notes |
|---|---|---|
| Linux | `uname -s` prints `Linux` | macOS and Windows aren't supported. |
| cgroup v2 | `stat -fc %T /sys/fs/cgroup` prints `cgroup2fs` | The default on current distributions (Ubuntu 22.04+, Debian 11+, Fedora 31+, Arch). Required: there is no cgroup v1 or hybrid fallback yet. |
| nftables | `nft --version` | Install the `nftables` package if it's missing. The daemon runs the `nft` command. |
| Python 3.11+ | `python3 --version` | |
| root | `sudo -v` | Only the daemon needs root. The CLI, including `pyvpn run`, works as a normal user. |

pyvpn doesn't connect to any VPN. Bring up your WireGuard, OpenVPN or other
interfaces with their own tools first; pyvpn only routes apps through
interfaces that already exist.

## 2. Install the package

The package on PyPI is **`snakevpn`**. The commands it installs are `pyvpn`
(the CLI) and `pyvpn-daemon` (the root daemon).

The daemon runs as root, so install it somewhere root can run it. The simplest
option is a dedicated virtual environment:

```bash
sudo python3 -m venv /opt/pyvpn
sudo /opt/pyvpn/bin/pip install snakevpn
sudo ln -s /opt/pyvpn/bin/pyvpn /opt/pyvpn/bin/pyvpn-daemon /usr/local/bin/
```

Or, with [pipx](https://pipx.pypa.io/):

```bash
sudo pipx install --global snakevpn
```

Check it:

```bash
pyvpn --version
pyvpn-daemon --version
```

### Optional extras

Install them with the package name, e.g. `pip install 'snakevpn[doh,re2]'`:

- `doh`: DNS over HTTPS upstreams (`"dns_protocol": "doh"`).
- `re2`: linear-time matching for regex rules in destination filters. Without
  it, the daemon refuses regex rules and complex wildcards; simple wildcards
  such as `*.example.com` still work.

## 3. Write a configuration

The daemon reads `/etc/pyvpn/config.json`, or the file named by `PYVPN_CONFIG`
or `--config`. Start with a minimal one and replace `wg0` with your own
interface:

```bash
sudo mkdir -p /etc/pyvpn
sudo tee /etc/pyvpn/config.json >/dev/null <<'EOF'
{
  "version": 1,
  "targets": [
    {"name": "vpn", "interface": "wg0"}
  ],
  "policies": [
    {"name": "VPN", "targets": ["vpn"], "on_down": "block",
     "apps": [{"name": "firefox"}]}
  ]
}
EOF
pyvpn test /etc/pyvpn/config.json
```

`pyvpn test` prints `ok`. On a mistake it exits 1. A file that isn't valid
JSON or breaks the schema prints `configuration validation failed`, without
the individual problems yet. A bad destination rule prints one line per rule
(`policy 'x' rule 2: error: …`) and ends with `errors found`. The [usage guide](usage.md#writing-a-configuration) explains every
field.

## 4. Run the daemon

### With systemd (recommended)

`pyvpn install` prints a systemd unit; `--write` installs it to
`/etc/systemd/system/pyvpn.service`. The unit's `ExecStart` is the
`pyvpn-daemon` found on your `PATH`. If it isn't on `PATH`, `ExecStart`
defaults to `/usr/bin/pyvpn-daemon`; pass `--exec-start` to choose the path:

```bash
sudo pyvpn install --write --exec-start "$(command -v pyvpn-daemon)"
sudo systemctl daemon-reload
sudo systemctl enable --now pyvpn
systemctl status pyvpn
```

The daemon logs to the journal:

```bash
journalctl -u pyvpn -f
```

### In the foreground

Handy for a first try:

```bash
sudo pyvpn-daemon --config /etc/pyvpn/config.json
```

Stop it with Ctrl-C. Stopping the daemon **leaves its rules installed**, so a
kill switch keeps blocking until the next daemon replaces the rules or you run
`pyvpn disable`.

### Daemon options

| Option | Default | Meaning |
|---|---|---|
| `--config FILE` | `$PYVPN_CONFIG` or `/etc/pyvpn/config.json` | Configuration file. |
| `--socket PATH` | `/run/pyvpn/pyvpn.sock` | API socket. The CLI's `--socket` must match. |
| `--state-dir DIR` | `/var/lib/pyvpn` | Saved state: enabled flag, cgroup slots, learned DNS addresses. |
| `--backend linux\|dry-run` | `linux` | `dry-run` logs each routing plan instead of installing it (see below). |
| `--no-process-watcher` | watcher on | Turns off automatic placement of processes matched by `exe`/`name` and similar selectors. |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. |

On start, the daemon sets `net.ipv4.conf.all.src_valid_mark=1` if needed,
so marked traffic passes strict reverse-path filtering.

## 5. Check that it works

```bash
pyvpn status
```

```text
daemon: enabled
1: VPN: dev via wg0 (vpn)
```

Each line shows the policy's current route: `dev via <interface> (<target>)`
while a target is up, `main` when it falls back to the normal route, and
`unreachable` while its kill switch is blocking. Continue with the
[usage guide](usage.md) to start apps in a policy.

## Try it without root (dry run)

`--backend dry-run` runs the daemon, the CLI, the target watcher and the DNS
stubs, but **routes and protects nothing**. It only logs the plan it would
install, and it keeps its cgroups in a scratch directory:

```bash
pyvpn-daemon --backend dry-run --config config.json \
  --socket /tmp/pyvpn.sock --state-dir /tmp/pyvpn-state
pyvpn --socket /tmp/pyvpn.sock status
```

## Upgrading

```bash
sudo /opt/pyvpn/bin/pip install -U snakevpn
sudo systemctl restart pyvpn
```

The new daemon replaces the installed rules in one atomic step, so there's no
window where a kill switch is open.

## Uninstalling

Remove pyvpn's rules **before** stopping the daemon for good, so nothing is
left installed:

```bash
sudo pyvpn disable
sudo systemctl disable --now pyvpn
sudo rm /etc/systemd/system/pyvpn.service
sudo systemctl daemon-reload
sudo rm -rf /var/lib/pyvpn /etc/pyvpn
sudo rm -rf /opt/pyvpn /usr/local/bin/pyvpn /usr/local/bin/pyvpn-daemon
```

To check that nothing is left:

```bash
sudo nft list table inet pyvpn      # "No such file or directory"
ip rule | grep 0x5059               # no output
```

## Troubleshooting install problems

| Symptom | Cause and fix |
|---|---|
| `pyvpn-daemon: the Linux routing backend is not part of this build` | You have 0.0.2 or older, whose daemon only runs with `--backend dry-run`. Upgrade to 0.0.3 or newer. |
| `cannot load the Linux routing backend (missing module ...)` | A dependency is missing from the daemon's environment. Reinstall `snakevpn` into it. |
| `cannot start: ...` and the daemon exits 1 | The config is invalid or uses a feature the daemon can't enforce yet; see [Not supported yet](usage.md#not-supported-yet). Check the message. |
| `pyvpn status` says `cannot contact pyvpn daemon` | The daemon isn't running, or the CLI uses a different `--socket`. |
| systemd: `status=203/EXEC` | `ExecStart` points at the wrong path. Rerun `pyvpn install --write --exec-start "$(command -v pyvpn-daemon)"`. |
