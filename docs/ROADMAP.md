# RATtler response roadmap

RATtler is moving from detection toward a layered endpoint response system.
Each layer must remain useful when later layers are unavailable, and enforcement
must fail safely. Release claims below describe implementation gates, not dates.

## 0.8 — Reviewed local response

Status: implemented.

- Plan quarantine without changing the endpoint.
- Bind approval to the exact SHA-256 and file metadata observed by the plan.
- Require a native operator confirmation in the macOS app.
- Move rather than delete, remove execute permissions, and retain a manifest.
- Restore only after integrity verification and refuse destination collisions.
- Keep a permission-restricted local audit trail.
- Never terminate a process or remove persistence automatically.

This layer deliberately refuses protected operating-system paths, links,
non-regular files, hard-linked files, targets inside the evidence store, changed
targets, and cross-filesystem moves.

## 0.8.2 — BluePulse sensor assurance

Status: implemented.

- Score confidence independently from threat findings.
- Surface unavailable or unhealthy defensive layers by name.
- Verify private local state, cursor, journal, and baseline permissions.
- Detect native collector stoppage with a bounded heartbeat age.
- Retain Endpoint Security sequence-gap accounting without timeline noise.
- Mark stale app reports and unsafe app placement as confidence problems.

BluePulse provides evidence within RATtler's current privilege boundary. It does
not claim same-user tamper resistance or protection after the native host quits;
those require the signed system-extension design below.

## 0.9 — Ransomware Defense

Status: implemented.

- Keep bounded local metadata snapshots of Desktop, Documents, and Pictures.
- Detect rapid rewrites, encryption-style extension replacement, ransom-note
  creation, mass deletion, and a modified or missing local canary.
- Keep threat findings separate from sensor availability in BluePulse.
- Expose protected-folder coverage, change velocity, and evidence in a dedicated
  native-app tab.
- Read no protected-file contents and upload no paths or findings.
- Run automatically every 60 seconds while the native host is running,
  including when its window is closed.

This layer is detection-only. It cannot stop writes already in progress or
recover encrypted files, and same-user malware could tamper with its local
state. Kernel-mediated authorization and root-owned state remain later gates.

## 0.10 — Recovery and prevention preview

Status: recovery implemented; native enforcement entitlement-gated.

- Provide an opt-in, 512 MiB, content-addressed Recovery Vault for common
  documents and photos.
- Retain up to three versions and freeze automatic updates after ransomware
  evidence so clean generations are not aged out.
- Verify stored hashes and recover into a new directory without overwriting an
  original file.
- Compile a separate Endpoint Security authorization guard that starts in
  shadow mode, attributes mutations to a PID and executable, and evaluates
  per-process mutation velocity, encryption-style renames, ransom notes, and
  canary access.
- Require an explicit command-line acknowledgement before the native guard can
  enter enforcement mode.

The downloadable community app can use Recovery Vault now. The authorization
guard cannot activate there until Apple grants the restricted entitlement and
the signed system-extension work below is complete.

Apple's current [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
model delivers kernel-mediated events to a user-space client. RATtler will
package and enable authorization only after the notification sensor and new
guard meet latency, event-loss, false-positive, and recovery budgets on every
supported macOS version.

The prevention client will:

- begin in shadow mode and record the decision it would have made;
- support only a small, versioned, locally cached policy format;
- allow Apple platform binaries and fail open when policy is absent or invalid;
- make decisions within a strict deadline without network access or file scans;
- deny only exact, reviewed indicators with an expiry and operator provenance;
- expose policy health, decision latency, and dropped coverage in the app; and
- require Apple's restricted Endpoint Security entitlement, Developer ID
  signing, notarization, Full Disk Access, and explicit user or MDM approval.

No release build will silently weaken System Integrity Protection or ask users
to install a legacy kernel extension.

## 0.11 — Loaded-code identity

Status: implemented.

- Record path, CDHash, signature type, Team ID, and signing identifier for a
  bounded set of user-writable loaded Mach-O candidates.
- Preserve those identities in continuous event state and emit a high-priority
  finding when CDHash or signer changes at the same loaded path.
- Include CDHash in new loaded-code integrity baselines without turning an
  older baseline's missing field into an upgrade alert.
- Explicitly identify macOS App Translocation paths and keep the evidence at
  review severity when the code is otherwise valid and consistently signed.
- Include the actor CDHash in native Endpoint Security events when available.

Notarization authenticates distribution; it is intentionally not used as a
substitute for runtime path, signature, identity-drift, or process-ancestry
evidence.

## 0.12 — Community hardening

Status: implemented.

- Add reviewed finding exceptions that require an exact rule, absolute path,
  cryptographic code or file identity, operator reason, and expiry.
- Refuse path-only exceptions and fail open without hiding findings when the
  local policy is invalid.
- Keep suppressed activity visible at informational severity and provide native
  confirmation plus removal controls in the app.
- Capture a bounded snapshot parent chain and start-time-derived process
  identity for process, connection, and loaded-code events.
- Correlate by process instance so ordinary PID reuse does not join unrelated
  activity.
- Pin CI actions and release packaging dependencies to reviewed revisions.

These controls remain local to the current user. They improve tuning and
snapshot evidence but do not claim root-owned policy protection or loss-aware
real-time lineage; those remain gated on the signed system extension.

## 0.13 — Deep Scan and open detection rules

Status: implemented.

- Add on-demand file and folder inspection to the native app.
- Bundle original community YARA rules with reproducible source hashes.
- Combine YARA evidence with SHA-256, Mach-O signing, filename, location, and
  bounded entropy context.
- Give individual YARA rules source-bound identities for precise exceptions.
- Keep scans local and cap file count, directory traversal, bytes, time, findings,
  per-file size, and returned file records.
- Refuse a symbolic-link target and never traverse links in selected folders.
- Connect exact-hash findings to reviewed quarantine and expiring exceptions.
- Provide a harmless end-to-end validation marker and rule authoring gates.

Deep Scan is not a full antivirus engine. It does not recursively unpack every
archive, emulate code, or claim that a match is malicious. Those capabilities
need dedicated limits, test corpora, and false-positive budgets.

## 0.14 — Detection engineering lab

Status: implemented.

- **ReplayForge:** replay versioned, harmless endpoint-event fixtures through the
  same correlation engine used by live scans.
- **Chainlight:** turn related process, persistence, network, loaded-code, file,
  and ransomware evidence into a time-ordered attack chain.
- Map tested detections to ATT&CK techniques without treating framework coverage
  as proof of detection quality.
- Publish machine-readable rule tests, expected findings, performance budgets,
  and negative fixtures so contributors can measure regressions in CI.
- Export a privacy-scrubbed investigation bundle with stable event and rule IDs.

This is RATtler's main differentiator: detections should be explainable,
replayable, and measurable by any contributor without installing malware.

## 0.15 — Persistence and system audit breadth

Status: implemented.

- Expand persistence coverage to login items, background task management,
  authorization plug-ins, configuration profiles, shell startup files, cron,
  periodic jobs, browser extensions, and developer-tool extensions.
- Track privacy-control database metadata and security-control state as
  configuration evidence, not automatic malware findings; TCC grant rows are
  intentionally not collected.
- Add signed-binary, notarization, ownership, and permission context while
  preserving behavioral evidence as the primary signal.
- Baseline each source independently so unavailable permissions degrade only the
  affected coverage.

All collectors have explicit object, depth, byte, and returned-evidence limits.
Current-user cron command contents and TCC grant rows are excluded from reports.
Notarization is distribution context only and never overrides behavioral
evidence.

## 0.16 — Continuous local operation

Status: implemented, except signed update metadata.

- Add a menu-bar controller that keeps scheduled local scans running after the
  main window closes and always exposes scan, pause/resume, reopen, and quit.
- Add explicit launch-at-login registration through macOS Service Management.
- Add opt-in local notifications for new high-priority findings without
  exposing endpoint paths in notification text.
- Persist a private native-operation heartbeat and last report; verify host PID,
  interval, freshness, pause state, and permissions through BluePulse.

Signed update metadata and rollback-safe in-app updates remain gated on a
Developer ID, hardened runtime, and notarization. The current update path is a
manual replacement from GitHub Releases and is described as such.

## 0.17 — Near-real-time protected-folder triggers

Status: implemented.

- Watch Desktop, Documents, and Pictures through native macOS FSEvents while
  RATtler is running.
- Coalesce ordinary bursts for two seconds and rate-limit triggered ransomware
  scans to one every ten seconds.
- Start a faster snapshot for encryption-style names, common ransom-note names,
  and FSEvents continuity-loss flags without treating a filename as a verdict.
- Reconcile user-space drops, kernel drops, event-ID wrap, and watched-root
  changes through a full bounded snapshot.
- Persist a private, path-free stream heartbeat and expose stopped, stale,
  unsafe, or unreconciled coverage through BluePulse.
- Keep the 60-second native scheduler as a fallback and make pause/resume govern
  both scheduled and event-triggered scans.

FSEvents cannot attribute a change to its responsible process or block a write.
Those capabilities remain gated on the Endpoint Security entitlement and signed
system-extension milestones below.

## 1.0 — Signed system extension and tamper evidence

Status: planned after prevention validation.

The native sensor and prevention client will be packaged as a hardened
[System Extension](https://developer.apple.com/documentation/systemextensions)
inside a notarized host app. Self-protection will focus on evidence and service
health, not undocumented kernel modification:

- verify the app, embedded engine, policy, and extension signatures at startup;
- surface extension removal, policy rollback, sensor stoppage, and audit gaps;
- keep privileged state in a root-owned location with least-privilege IPC;
- bind policy revisions to signed metadata and monotonic versions;
- use launch and extension health checks rather than respawn loops; and
- provide clean uninstall and recovery paths.

## 1.1 — Fleet response

Status: planned after the local response and privilege boundaries are stable.

Fleet control will use enrolled device identities and fixed, typed actions—not a
remote shell. The initial action vocabulary will be scan, collect a bounded
report, plan quarantine, apply an already-reviewed quarantine, and restore.

Every action will require:

- mutual authentication plus a separately signed command envelope;
- tenant, device, action, policy revision, nonce, expiry, and idempotency key;
- role-based approval and an optional second approver for destructive actions;
- replay rejection and bounded offline queues;
- endpoint and server audit records with correlated action IDs; and
- a local emergency-disable and key-rotation path.

Network isolation, process termination, persistence removal, and arbitrary file
collection remain out of the first fleet release because their blast radius and
privacy requirements need separate design and testing.

## Research backlog

The other blue-team concepts remain recorded for later exploration:

- **HoneyHome:** harmless endpoint decoys that alert when opened or copied.
- **ExtensionWatch:** browser and IDE extension permission and publisher drift.

These are ideas, not shipped RATtler capabilities. Each needs its own privacy,
false-positive, and safe-validation design before implementation.

## Release gates

A layer moves from preview to supported only after unit and integration tests,
adversarial path and race tests, upgrade/rollback tests, endpoint performance
budgets, signed artifacts, documented recovery, and validation against clean and
intentionally instrumented macOS images. A detection or shadow decision is never
described as prevention.
