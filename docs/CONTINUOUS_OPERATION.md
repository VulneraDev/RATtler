# Continuous local operation

RATtler 0.16 moves scheduled endpoint scans into the native macOS host. The
host remains available from the menu bar after the main window closes and runs
a bounded scan every 60 seconds while monitoring is active.

## Everyday controls

Use the **R** menu-bar item or **Settings → Monitoring**:

- **Scan Now** runs a manual scan even when scheduling is paused.
- **Pause Monitoring** stops future scheduled scans but lets a scan already in
  progress finish. It keeps the menu-bar controller and manual scan available.
  BluePulse reports the paused state as reduced confidence.
- **Start at Login** asks macOS Service Management to register the main app. If
  macOS requires approval, open **System Settings → General → Login Items**.
- **Finding Notifications** are optional. macOS asks for permission the first
  time they are enabled.
- **Quit RATtler** stops the native host. Closing only the main window does not.

Notifications are emitted only when the set of critical or high-priority rule
IDs changes, including across app restarts. They contain a count and an
instruction to open RATtler; paths, filenames, process names, and network
endpoints are intentionally omitted.

## Evidence behind the control

The native host writes
`~/Library/Application Support/RATtler/operation-state.json` with mode `0600`.
The record is replaced atomically and contains only:

- schema version;
- active or paused status;
- native host PID;
- scheduled interval;
- heartbeat and last-scan timestamps;
- menu-bar availability; and
- whether launch at login is currently enabled.

The `continuous_operation` sensor rejects symbolic links, non-regular files,
oversized or invalid JSON, broad permissions, unexpected owners, invalid
intervals, and malformed timestamps. It checks that the recorded PID is alive
and considers a heartbeat stale after the greater of three intervals or three
minutes. BluePulse includes the result in its confidence calculation.

The latest valid report is also stored privately as `last-report.json`, so the
interface can show the previous evidence immediately after launch. An active
host starts a fresh scan as soon as the interface loads.

## What this does not claim

This is reliable current-user scheduling, not kernel-level prevention or
tamper-proof monitoring. Malware already running as the same user may be able
to stop RATtler or replace current-user state. BluePulse makes a stale, stopped,
paused, or unsafe state visible the next time evidence is inspected; it cannot
prevent that action.

Root-owned state, system-extension lifecycle evidence, execution prevention,
and protected real-time event collection remain gated on Apple's restricted
Endpoint Security entitlement and signed system-extension distribution.

RATtler 0.16 also does not perform an in-app update. Updates are manual: quit
RATtler, download the new architecture-specific ZIP from GitHub Releases, and
replace the old app. Signed update metadata and rollback protection will be
added only after Developer ID signing, hardened runtime, and notarization are
available.

## CLI verification

Developers can add the operation heartbeat to a normal scan:

```sh
rattler --operation-state "$HOME/Library/Application Support/RATtler/operation-state.json" --pretty
```

The option reads and validates the record; it does not create, pause, resume,
or register the app.
