# RATtler CLI guide

The desktop app is the simplest way to use RATtler on a Mac. This guide is for
developers and operators who want the command line.

## Install and scan

Python 3.9.2 or newer is required.

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

## Persistence Atlas

Every normal macOS scan includes a `persistence_atlas` sensor. Its `sources`
array reports health, limits, object counts, and a bounded preview for eleven
autostart and configuration sources. Findings use `RAT-PERSIST-101` through
`RAT-PERSIST-109` for precise ownership, permission, symlink, preload,
staging-path, signing, and update-channel signals.

Current-user cron jobs are inspected through a fixed `crontab -l` argument list,
but command text is never returned; only line number and risk booleans are kept.
TCC grant rows are not read. Full source and field details are in the
[Persistence Atlas guide](PERSISTENCE_ATLAS.md).

## Detection Lab

Replay the bundled safe fixtures through the production correlation engine:

```sh
rattler lab --pretty suite detections/fixtures
rattler lab --pretty replay detections/fixtures/staged-network-persistence.json
rattler lab --pretty bundle detections/fixtures/staged-network-persistence.json
```

ReplayForge returns `0` when all detection contracts pass, `1` for an assertion
regression, and `2` for an invalid or unsafe fixture. Chainlight output includes
stable evidence chains and conservative ATT&CK context. `bundle` emits only the
privacy-tokenized investigation view. See the [fixture authoring guide](DETECTION_LAB.md).

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

With `--state`, `--journal`, `--baseline`, `--native-events`,
`--operation-state`, or `--fsevents-state`, BluePulse also checks the
corresponding local artifacts.
Private state must remain owned by the current user and inaccessible to group or
other users. A native event stream may be readable by a dedicated group, but it
must not be group- or world-writable.

The macOS app supplies `--operation-state` automatically. For a developer scan:

```sh
rattler --operation-state "$HOME/Library/Application Support/RATtler/operation-state.json" --pretty
```

The bounded assurance sensor validates schema, permissions, ownership,
heartbeat freshness, scheduling interval, pause state, and whether the native
host PID is still alive. It is read-only and does not start or control the app.

The macOS app also supplies `--fsevents-state` automatically. Its path-free
health record validates the protected-folder stream, watched-root count,
aggregate triggers, heartbeat, host PID, and unreconciled event loss. The CLI
does not create an FSEvents stream itself; the native app owns that lifecycle.

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
possible ransom-note names, and mass deletion. In the native app, FSEvents
triggers this snapshot within seconds, with burst coalescing and a ten-second
scan rate limit. The CLI example above remains interval-based. Neither mode is
real-time write prevention; opt-in recovery is separate.

## Recovery Vault

Plan the initial local backup, then apply it explicitly:

```sh
rattler recovery backup --store ~/.rattler/recovery \
  --root ~/Desktop --root ~/Documents --root ~/Pictures --pretty
rattler recovery backup --store ~/.rattler/recovery \
  --root ~/Desktop --root ~/Documents --root ~/Pictures --apply --pretty
rattler recovery status --store ~/.rattler/recovery --pretty
```

The macOS app runs detection before each automatic refresh and passes its
private vault freeze marker with `--abort-if-exists`. If ransomware evidence
appears while a refresh is running, the backup exits without replacing the last
complete manifest. This option is intended for trusted local orchestration; it
does not decide whether activity is ransomware.

The default quota is 512 MiB and the per-file limit is 16 MiB. Only common
document and photo extensions are copied, objects are content-addressed, and up
to three versions are retained per path. The macOS app refreshes an enabled
vault after detection and freezes it when a ransomware finding appears.

Recovery is also planned before application and always targets a new directory:

```sh
rattler recovery restore-all --store ~/.rattler/recovery \
  --destination ~/Desktop/RATtler-Recovered --pretty
rattler recovery restore-all --store ~/.rattler/recovery \
  --destination ~/Desktop/RATtler-Recovered --apply --pretty
```

The destination must not already exist. Stored object hashes are verified, and
the command never writes over an original file.

Create one password-encrypted file on a mounted USB drive. RATtler prompts for
the password twice without echoing it:

```sh
rattler recovery export \
  --store ~/.rattler/recovery \
  --destination /Volumes/RECOVERY/RATtler-Recovery.rattlervault \
  --apply --pretty
```

Restore from that copy into a new directory:

```sh
rattler recovery restore-bundle \
  --archive /Volumes/RECOVERY/RATtler-Recovery.rattlervault \
  --destination ~/Desktop/RATtler-USB-Recovery \
  --apply --pretty
```

The desktop app is safer and simpler because its native secure fields avoid a
shell. Scripts may opt into one-line standard input with `--password-stdin`, but
must never place the password directly in an argument or source file. Export
requires at least 12 characters. The password is never stored and cannot be
reset. See [Encrypted offline recovery](ENCRYPTED_RECOVERY.md).

## Integrity baseline

Create a baseline only after reviewing a clean scan:

```sh
rattler --create-baseline ~/.rattler/baseline.json --pretty
rattler --baseline ~/.rattler/baseline.json --pretty
rattler --baseline ~/.rattler/baseline.json --watch --changes-only
```

The baseline tracks SHA-256 content, size, permissions, ownership, and symlink
targets. For active Mach-O code in user-writable locations it also records the
signing CDHash when available. Eligible Persistence Atlas file sources are
included by default. If one Atlas source becomes unreadable, only that source's
comparison degrades; it does not emit false missing-file findings. The baseline
is mode `0600`. Same-user malware could replace it, so keep a protected copy
when higher assurance is required.

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
