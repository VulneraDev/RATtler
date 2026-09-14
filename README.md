# RATtler

RATtler is an open-source, read-only anti-RAT endpoint monitor. It combines native
antivirus health with explainable behavioral checks for suspicious process
locations, launchd persistence and preload injection, and exposed TCP listeners.
RATtler does not upload endpoint data.

Supported checks:

- Windows: Microsoft Defender antivirus, real-time protection, and signatures
- macOS: Gatekeeper and installed XProtect package metadata
- Linux/other Unix: ClamAV engine availability and `clamd` process state

Behavioral sensors in the current macOS-first build:

- Processes running from temporary, download, cache, or deleted locations
- LaunchAgents and LaunchDaemons using risky, relative, missing, or world-writable executables
- `DYLD_INSERT_LIBRARIES` and `LD_PRELOAD` configured through launchd persistence
- TCP services listening on every interface, correlated to their process path
- Deleted or untrusted Mach-O images mapped into protected processes
- Code-signing and Team ID mismatches for modules loaded from user-writable paths

Findings are indicators for review, not malware verdicts. RATtler never kills a
process, deletes a file, or changes a persistence entry.

## Quick start

Python 3.9 or newer is required.

```sh
python3 -m pip install -e .
rattler --pretty
rattler --watch --interval 30 --changes-only
```

Create a known-good integrity baseline only after reviewing a clean scan, then
include it in later scans:

```sh
rattler --create-baseline ~/.rattler/baseline.json --pretty
rattler --baseline ~/.rattler/baseline.json --pretty
rattler --baseline ~/.rattler/baseline.json --watch --changes-only
```

The baseline tracks SHA-256 content, size, permissions, ownership, and symlink
targets for launchd plists, their existing executables, and active Mach-O code in
user-writable locations. It is written atomically with mode `0600`. Because
same-user malware could replace both files and a local baseline, keep a protected
or remotely attested copy when using RATtler for higher-assurance monitoring.

Enable event correlation by giving RATtler a state path. A journal is optional:

```sh
rattler --state ~/.rattler/state.json --pretty
rattler --state ~/.rattler/state.json \
  --journal ~/.rattler/events.jsonl \
  --watch --interval 30 --changes-only
```

The first run records current state without emitting a flood of historical
events. Later runs report process starts, new listeners and connections,
persistence changes, and newly loaded user-writable Mach-O images. Related events
are correlated across 15 minutes by default; change this with `--event-window`.

State and journal files contain local process paths and network endpoints. They
are written with mode `0600` and never uploaded by RATtler. The JSONL journal
rotates to `.1` at 10 MiB by default; use `--journal-max-bytes` to adjust it. Run
only one state writer per path.

## Safe validation canary

`tools/safe_canary.py` locally compiles a tiny helper and emulates three RAT
indicators without containing malicious logic: execution from a temporary
directory, a loopback-only TCP connection, and
a disabled LaunchAgent that is never loaded. It runs for at most five minutes and
removes its process, temporary directory, and labeled plist in a `finally` block.

Initialize event state before starting the canary, run the canary in another
terminal, then scan using the same state file:

```sh
rattler --state /tmp/rattler-canary-state.json
python3 tools/safe_canary.py --duration 45
rattler --state /tmp/rattler-canary-state.json --pretty
```

RATtler should report snapshot findings plus `RAT-CORR-001` for the staged
process and loopback connection and `RAT-CORR-003` for the disabled persistence
artifact. The canary does not invoke `launchctl`, accept remote traffic, transfer
data, or install executable persistence.

Without installing:

```sh
PYTHONPATH=src python3 -m rattler --pretty
```

Every report contains endpoint-protection state, sensor coverage, risk-ranked
findings, and an overall status. One-shot exit codes are `0` healthy, `1`
degraded, `2` unknown, and `3` unhealthy. `Ctrl-C` returns `130` in watch mode.

RATtler executes only fixed command argument lists, never a shell, and has no
network code. Run it as a normal user; do not grant administrator/root privileges.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The provider boundary in `src/rattler/providers.py` is deliberately small. New
endpoint products can implement `Provider.checks()` and return normalized
`Check` values. Please avoid collecting usernames, process arguments, file paths,
or file contents in providers.

## Project status

This is an alpha anti-RAT foundation, not a replacement for antivirus/EDR. The
behavioral sensors are macOS-first; Windows and Linux currently receive antivirus
health plus the portable process/listener checks. Loaded-image inspection covers
file-backed Mach-O mappings visible to the current user. Anonymous executable
memory, in-place modification within an application's own signed bundle, and
kernel-level injection require deeper OS telemetry or a persistent hash baseline
and remain future work. Validate RATtler against the endpoint images you operate
before alerting.

Contributions are welcome under the MIT license. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).
