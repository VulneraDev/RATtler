# RATtler CLI guide

The desktop app is the simplest way to use RATtler on a Mac. This guide is for
developers and operators who want the command line.

## Install and scan

Python 3.9 or newer is required.

```sh
python3 -m pip install -e .
rattler --pretty
rattler --watch --interval 30 --changes-only
```

Without installing:

```sh
PYTHONPATH=src python3 -m rattler --pretty
```

One-shot exit codes are `0` healthy, `1` degraded, `2` unknown, and `3`
unhealthy. `Ctrl-C` returns `130` in watch mode.

## Integrity baseline

Create a baseline only after reviewing a clean scan:

```sh
rattler --create-baseline ~/.rattler/baseline.json --pretty
rattler --baseline ~/.rattler/baseline.json --pretty
rattler --baseline ~/.rattler/baseline.json --watch --changes-only
```

The baseline tracks SHA-256 content, size, permissions, ownership, and symlink
targets for launchd plists, startup executables, and active Mach-O code in
user-writable locations. It is mode `0600`. Same-user malware could replace a
local baseline, so keep a protected copy when higher assurance is required.

## Event correlation

```sh
rattler --state ~/.rattler/state.json --pretty
rattler --state ~/.rattler/state.json \
  --journal ~/.rattler/events.jsonl \
  --watch --interval 30 --changes-only
```

The first run initializes state quietly. Later scans report process starts, new
listeners and connections, persistence changes, and newly loaded code. The
default correlation window is 15 minutes; change it with `--event-window`.
The JSONL journal rotates at 10 MiB by default.

## Quarantine and restore

The first quarantine command is a dry run. Applying it requires the exact hash
returned by that dry run:

```sh
rattler response quarantine /absolute/path/to/file \
  --reason "RATtler finding review" --pretty
rattler response quarantine /absolute/path/to/file \
  --reason "RATtler finding review" \
  --expected-sha256 <sha256-from-dry-run> --apply --pretty
rattler response list --pretty
```

Restore is also reviewed before application:

```sh
rattler response restore <entry-id> --pretty
rattler response restore <entry-id> --apply --pretty
```

The default store is `~/.rattler/quarantine`. RATtler refuses links,
non-regular files, protected operating-system paths, files already inside the
store, cross-filesystem moves, changed hashes, and restore collisions. The store
is permission-restricted but not tamper-proof against code already running as
the same user.

## Safe validation canary

`tools/safe_canary.py` emulates three RAT indicators without malicious logic: a
temporary-directory process, a loopback-only connection, and a disabled
LaunchAgent that is never loaded.

```sh
rattler --state /tmp/rattler-canary-state.json
python3 tools/safe_canary.py --duration 45
rattler --state /tmp/rattler-canary-state.json --pretty
```

The canary does not invoke `launchctl`, accept remote traffic, transfer data, or
install executable persistence. It self-cleans in a `finally` block.

## Native telemetry

Live macOS Endpoint Security collection requires Apple’s restricted entitlement,
provisioning, Full Disk Access, and root execution. See the
[native sensor guide](../native/macos/README.md). Ordinary scanning and response
commands should run as a normal user.

RATtler executes fixed argument lists, never a shell, and contains no network
upload code. State and journal files include local paths and network endpoints;
keep them private and use one state writer per path.
