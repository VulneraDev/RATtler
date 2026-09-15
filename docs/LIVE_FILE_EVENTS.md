# Live protected-folder events

RATtler 0.17 adds a native macOS FSEvents stream for Desktop, Documents, and
Pictures. While the app is running, a protected-folder change schedules a
bounded ransomware snapshot instead of waiting only for the next 60-second
scan.

## What happens after a file change

1. macOS reports file-level changes with a one-second FSEvents latency.
2. RATtler coalesces ordinary bursts for two seconds. A suspicious extension,
   common ransom-note filename, or stream-loss flag shortens that delay.
3. RATtler rate-limits triggered scans to one every ten seconds.
4. The existing 25,000-file metadata snapshot compares created, modified,
   deleted, and renamed files and applies the ransomware rules.
5. Any finding remains explainable in the Ransomware and Findings views.

Detection runs before automatic Recovery Vault refresh work. A large vault can
continue refreshing in the background without holding the file-event scan; a
ransomware finding freezes the vault and aborts that refresh before it can
replace the last complete manifest.

FSEvents is the trigger, not the verdict. A normal change starts a scan but is
not labeled malicious. The scanner still requires multiple defined signals
before it reports ransomware-like activity.

## Continuity and event loss

FSEvents can request a full rescan after a user-space or kernel drop, event-ID
wrap, or watched-root change. RATtler records that state as unreconciled loss
and starts a snapshot. The state is cleared only after a scan that began after
the loss completes; the following report reflects restored continuity. A second
loss during that scan stays pending for the next reconciliation.

The app writes a mode-`0600` health record at
`~/Library/Application Support/RATtler/fsevents-state.json`. It contains the
host PID, heartbeat, stream status, watched-root count, aggregate event and
scan counters, loss count, and last event ID. It does not contain file paths.
BluePulse validates its schema, ownership, permissions, host process, freshness,
stream state, and unreconciled-loss flag on every scan.

## Pause and fallback behavior

Pausing monitoring stops file-event-triggered and scheduled scans. Manual scans
still work. Resuming performs a fresh scan. If the FSEvents stream is
unavailable, RATtler reports that coverage gap and the native 60-second
scheduler remains available.

## Current boundary

This is near-real-time detection, not write prevention. FSEvents does not give
RATtler the responsible process identity and cannot block a write. Process
attribution and kernel-mediated authorization require Apple's restricted
Endpoint Security entitlement, a signed system extension, explicit user or MDM
approval, and separate false-positive and latency validation. RATtler does not
claim those capabilities in the community build.
