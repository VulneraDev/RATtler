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

## Deep Scan

Install the optional YARA engine and inspect one selected file or folder:

```sh
python3 -m pip install -e '.[yara]'
rattler files scan ~/Downloads --rules rules --pretty
```

The desktop release already includes the YARA engine and RATtler's community
rules. The CLI keeps it optional so the normal endpoint-health command stays
dependency-light. Repeat `--rules` to combine reviewed rule files or folders.
Only `.yar` and `.yara` files are compiled.

Deep Scan calculates SHA-256, samples entropy, recognizes Mach-O content,
checks signing identity on macOS, and reports disguised executable names. YARA
results include the rule name, tags, confidence metadata, source filename, and
SHA-256 of the exact rule source. A rule-specific ID plus the scanned file hash
prevents an exception for one rule from hiding a different rule match.

Defaults are intentionally bounded: 2,000 files, 64 MiB per file, 512 MiB total,
120 seconds, 10,000 visited directories, 500 findings, and 250 reported file records.
Symbolic-link targets are refused and links inside folders are not followed.
Override the byte and file limits only for a controlled investigation:

```sh
rattler files scan ./samples --rules ./rules \
  --max-files 5000 --max-file-bytes 134217728 \
  --max-total-bytes 1073741824 --max-seconds 300 --pretty
```

Use `--no-recursive` for only the chosen folder's immediate files and
`--exceptions ~/.rattler/exceptions.json` to apply reviewed, expiring,
file-hash-bound exceptions. Deep Scan returns `0` with no active match, `1` when
findings need review, `3` for a high-priority match, and `2` when the request is
refused. Coverage and safety-limit details remain explicit in the JSON even
when no threat indicator matched.

## BluePulse confidence

Every scan includes a `bluepulse` sensor result. It reports high, reduced, or
low confidence in the sensors available to that scan. Threat findings and
confidence remain separate: high confidence does not mean the endpoint is clean.

With `--state`, `--journal`, `--baseline`, or `--native-events`, BluePulse also
checks the corresponding local artifacts. Private state must remain owned by the
current user and inaccessible to group or other users. A native event stream may
be readable by a dedicated group, but it must not be group- or world-writable.

Native collection is considered stale after 45 seconds without a heartbeat or
event. The collector emits a heartbeat every 15 seconds. Heartbeats are consumed
as health evidence and do not appear in the activity timeline.

## Ransomware monitoring

Persist a bounded metadata snapshot and compare it with later scans:

```sh
rattler --ransomware-state ~/.rattler/ransomware-state.json \
  --ransomware-root ~/Desktop \
  --ransomware-root ~/Documents \
  --ransomware-root ~/Pictures \
  --watch --interval 60 --changes-only --pretty
```

Without explicit roots, Desktop, Documents, and Pictures are used. The sensor
tracks paths, size, modification time, and inode for at most 25,000 files; set a
different positive bound with `--ransomware-max-files`. It does not read the
contents of protected files. A small canary beside the private state file
detects tampering, and BluePulse checks both artifacts' permissions.

Rules report canary damage, repeated encryption-style extensions, bulk rewrites,
possible ransom-note names, and mass deletion. This sensor is scan-based while
RATtler is open, not real-time write prevention; opt-in recovery is separate.

## Recovery Vault

Plan the initial local backup, then apply it explicitly:

```sh
rattler recovery backup --store ~/.rattler/recovery \
  --root ~/Desktop --root ~/Documents --root ~/Pictures --pretty
rattler recovery backup --store ~/.rattler/recovery \
  --root ~/Desktop --root ~/Documents --root ~/Pictures --apply --pretty
rattler recovery status --store ~/.rattler/recovery --pretty
```

The default quota is 512 MiB and the per-file limit is 16 MiB. Only common
document and photo extensions are copied, objects are content-addressed, and up
to three versions are retained per path. The macOS app refreshes an enabled
vault before scans and freezes it when a ransomware finding appears.

Recovery is also planned before application and always targets a new directory:

```sh
rattler recovery restore-all --store ~/.rattler/recovery \
  --destination ~/Desktop/RATtler-Recovered --pretty
rattler recovery restore-all --store ~/.rattler/recovery \
  --destination ~/Desktop/RATtler-Recovered --apply --pretty
```

The destination must not already exist. Stored object hashes are verified, and
the command never writes over an original file.

## Integrity baseline

Create a baseline only after reviewing a clean scan:

```sh
rattler --create-baseline ~/.rattler/baseline.json --pretty
rattler --baseline ~/.rattler/baseline.json --pretty
rattler --baseline ~/.rattler/baseline.json --watch --changes-only
```

The baseline tracks SHA-256 content, size, permissions, ownership, and symlink
targets. For active Mach-O code in user-writable locations it also records the
signing CDHash when available. It is mode `0600`. Same-user malware could
replace a local baseline, so keep a protected copy when higher assurance is
required.

## Event correlation

```sh
rattler --state ~/.rattler/state.json --pretty
rattler --state ~/.rattler/state.json \
  --journal ~/.rattler/events.jsonl \
  --watch --interval 30 --changes-only
```

The first run initializes state quietly. Later scans report process starts, new
listeners and connections, persistence changes, and newly loaded code. Risky
loaded-image state includes its path, CDHash, signing kind, Team ID, and App
Translocation status; a CDHash or signer change at the same path becomes a
high-priority finding. The default correlation window is 15 minutes; change it
with `--event-window`.
The JSONL journal rotates at 10 MiB by default.

Snapshot process events include a bounded parent chain and an instance identity
derived from PID, parent PID, executable, and process start time. Correlation
uses that identity so unrelated processes that reuse a PID are not joined. This
is best-effort snapshot context; the entitlement-gated native collector remains
the future source for loss-aware real-time ancestry.

## Reviewed exceptions

Create an exception as a dry run, then explicitly apply the reviewed plan:

```sh
rattler exceptions --policy ~/.rattler/exceptions.json --pretty add \
  --rule-id RAT-INJECT-005 --path /absolute/path/plugin.dylib \
  --cdhash <40-or-64-character-cdhash> --reason "Reviewed internal plugin"
rattler exceptions --policy ~/.rattler/exceptions.json --pretty add \
  --rule-id RAT-INJECT-005 --path /absolute/path/plugin.dylib \
  --cdhash <40-or-64-character-cdhash> --reason "Reviewed internal plugin" --apply
rattler --exceptions ~/.rattler/exceptions.json --pretty
```

An exception requires an exact rule and absolute path plus a CDHash, SHA-256,
or Team ID and signing identifier. It must include a reason, lasts 30 days by
default, and cannot exceed 90 days. Path-only exceptions are refused. Matching
findings stop affecting risk status, while linked events remain in the activity
timeline at informational severity.

```sh
rattler exceptions --policy ~/.rattler/exceptions.json --pretty list
rattler exceptions --policy ~/.rattler/exceptions.json --pretty remove <entry-id>
rattler exceptions --policy ~/.rattler/exceptions.json --pretty remove <entry-id> --apply
```

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
