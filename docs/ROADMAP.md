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
not claim same-user tamper resistance or background protection while the app is
closed; those require the signed system-extension design below.

## 0.9 — Ransomware Defense

Status: implemented.

- Keep bounded local metadata snapshots of Desktop, Documents, and Pictures.
- Detect rapid rewrites, encryption-style extension replacement, ransom-note
  creation, mass deletion, and a modified or missing local canary.
- Keep threat findings separate from sensor availability in BluePulse.
- Expose protected-folder coverage, change velocity, and evidence in a dedicated
  native-app tab.
- Read no protected-file contents and upload no paths or findings.
- Run automatically every 60 seconds while the app is open.

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

- **Chainlight:** visual, cross-source attack chains with portable temporal rules.
- **HoneyHome:** harmless endpoint decoys that alert when opened or copied.
- **ExtensionWatch:** browser and IDE extension permission and publisher drift.
- **ReplayForge:** safe synthetic event replay for testing detections in CI.

These are ideas, not shipped RATtler capabilities. Each needs its own privacy,
false-positive, and safe-validation design before implementation.

## Release gates

A layer moves from preview to supported only after unit and integration tests,
adversarial path and race tests, upgrade/rollback tests, endpoint performance
budgets, signed artifacts, documented recovery, and validation against clean and
intentionally instrumented macOS images. A detection or shadow decision is never
described as prevention.
