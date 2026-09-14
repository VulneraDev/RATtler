# RATtler

RATtler is an open-source anti-RAT endpoint monitor with reviewed local
response. It combines native antivirus health with explainable behavioral checks
for suspicious process locations, launchd persistence and preload injection, and
exposed TCP listeners. RATtler does not upload endpoint data.

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
- Native process, memory, task-port, tracing, and remote-thread telemetry when the
  optional macOS Endpoint Security sensor is provisioned

Findings are indicators for review, not malware verdicts. RATtler never deletes
a file and does not automatically kill processes or alter persistence. An
operator can manually quarantine one reviewed file; RATtler never applies that
action automatically.

## Quick start

Python 3.9 or newer is required.

```sh
python3 -m pip install -e .
rattler --pretty
rattler --watch --interval 30 --changes-only
```

## macOS desktop app

RATtler 0.8 includes a native Community Preview with Dashboard, Findings, Sensor
Health, Activity, and Settings views. It supports one-click scans, automatic
refresh, reviewed integrity baselines, local event history, and JSON report
export. Eligible file-backed findings also offer a reviewed quarantine action.

### Screenshots

These documentation renders use deterministic synthetic endpoint data; no
malicious software was installed to produce them.

Healthy endpoint:

![RATtler dashboard showing a healthy endpoint](docs/images/rattler-healthy.png)

Risk detected (safe synthetic demo data):

![RATtler dashboard showing critical, high, and medium risk findings](docs/images/rattler-risk.png)

Build and open the development app:

```sh
./app/macos/build.sh
open build/macos/RATtler.app
```

Create a portable ZIP download that bundles the detection engine and does
not require Python on the destination Mac:

```sh
python3 -m pip install pyinstaller
./app/macos/build.sh --portable --archive
```

Tagged releases publish separate Apple Silicon and Intel ZIPs on
[GitHub Releases](https://github.com/VulneraDev/RATtler/releases). Download the
archive and matching `.sha256` file for your Mac, verify the checksum, then move
`RATtler.app` into Applications. The preview is ad-hoc signed but not
Apple-notarized, so use Control-click → Open for its first launch. All UI data
remains under
`~/Library/Application Support/RATtler`; the interface loads no remote code. See
[`app/macos/README.md`](app/macos/README.md) for packaging details.

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

## Native macOS telemetry

Milestone 0.6 adds a small C collector for Apple's Endpoint Security framework.
It is notification-only: it observes activity and cannot authorize, deny, kill,
or quarantine anything. The collector reports process execution, memory mapping
and protection changes, task-port access, tracing, remote-thread creation, and
code-signature invalidation. RATtler's Python bridge turns those records into
normal events and findings, including a critical correlation when task access is
followed by cross-process thread creation.

Build the collector and initialize RATtler's cursor before starting live event
collection:

```sh
make -C native/macos
install -d -m 700 ~/.rattler
install -m 600 /dev/null ~/.rattler/native-events.jsonl
rattler --state ~/.rattler/state.json \
  --native-events ~/.rattler/native-events.jsonl --pretty
```

After Apple has approved your developer team for the Endpoint Security client
entitlement and the binary has been provisioned and signed, start the collector
in a separate terminal and then run RATtler continuously:

```sh
sudo native/macos/build/rattler-es-sensor \
  --output ~/.rattler/native-events.jsonl
rattler --state ~/.rattler/state.json \
  --native-events ~/.rattler/native-events.jsonl \
  --journal ~/.rattler/events.jsonl --watch --changes-only
```

Live Endpoint Security use also requires Full Disk Access and root execution.
An ordinary unsigned local build is still useful for source and CI validation,
but macOS will refuse to connect it to Endpoint Security. See
[`native/macos/README.md`](native/macos/README.md) for signing details. The
native log and cursor contain local paths, process identifiers, signing IDs, and
Team IDs; keep them private and run only one cursor writer per state path.
For a production deployment, place the event log in a root-controlled directory
and grant a dedicated reader only the minimum access it needs; the home-directory
commands above are for local evaluation.

## Reviewed quarantine

RATtler 0.8 can move one exact regular file into a private local evidence store.
The first command is a dry run; applying the action requires its SHA-256 so a
changed path cannot be moved under an earlier approval:

```sh
rattler response quarantine /absolute/path/to/file \
  --reason "RATtler finding review" --pretty
rattler response quarantine /absolute/path/to/file \
  --reason "RATtler finding review" \
  --expected-sha256 <sha256-from-dry-run> --apply --pretty
rattler response list --pretty
```

Restores are also reviewed before they are applied:

```sh
rattler response restore <entry-id> --pretty
rattler response restore <entry-id> --apply --pretty
```

The default CLI store is `~/.rattler/quarantine`; the desktop app uses
`~/Library/Application Support/RATtler/quarantine`. Payloads lose execute
permissions while quarantined. Manifests retain the original path and mode, and
`audit.jsonl` records quarantine and restore events. RATtler refuses links,
non-regular files, protected operating-system paths, files already inside the
store, cross-filesystem moves, hash changes, and restore collisions. Quarantine
does not stop a process that is already running. The store is
permission-restricted, but it is not tamper-proof against code already running
as the same user.

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
network code. Run the Python scanner and response commands as a normal user.
Only the separately provisioned native Endpoint Security collector requires
root.

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
file-backed Mach-O mappings visible to the current user. The optional native
sensor adds memory-permission and cross-process activity telemetry, but it
remains detection-only and does not inspect memory contents. Manual, reversible
file quarantine is available in 0.8. Endpoint Security authorization, signed
system-extension self-protection, and fleet response are staged in the
[response roadmap](docs/ROADMAP.md); they are not claimed as finished. Validate
RATtler against the endpoint images you operate before alerting or enabling
future enforcement.

Contributions are welcome under the MIT license. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).
