# Changelog

## 0.18.0

- Add an interactive CSS 3D endpoint overview to the Dashboard with selectable
  Platform Protection, Processes, Network, Persistence, Files, and BluePulse
  layers backed by the current report
- Add pointer perspective, keyboard selection, direct investigation links, and
  reduced-motion behavior without introducing remote code or dependencies
- Move automatic Recovery Vault refreshes after detection and run them outside
  the scan path so large backups do not delay FSEvents-triggered scans
- Add a freeze-marker abort contract that refuses to replace the last complete
  recovery manifest when ransomware evidence appears during a refresh
- Expose background vault-refresh state in the Ransomware view and track native
  engine child tasks for clean shutdown
- Validate detection during an active synthetic 220-file vault refresh: the
  file event triggered and completed healthy while backup work was still active

## 0.17.0

- Add a native file-level FSEvents stream for Desktop, Documents, and Pictures
  that triggers bounded ransomware scans within seconds while RATtler runs
- Coalesce ordinary file bursts for two seconds and rate-limit repeated scans
  to one every ten seconds, with faster triggers for suspicious names and loss
- Detect user-space drops, kernel drops, event-ID wrap, and watched-root changes;
  keep loss pending until a newer full snapshot completes successfully
- Add a private path-free stream heartbeat and a `native_file_events` assurance
  sensor that verifies ownership, permissions, schema, host PID, and freshness
- Extend BluePulse, Ransomware Defense, Settings, reproducible screenshots, CLI
  docs, and the roadmap with honest near-real-time coverage and limitations
- Validate the complete path on macOS with a harmless file creation: one native
  event triggered one scan and returned healthy without retaining its path

## 0.16.0

- Move scheduled scans from the WebKit interface into a native 60-second macOS
  scheduler that continues while the main window is closed
- Add a menu-bar controller for reopen, scan now, pause/resume, login-item,
  notification, and explicit quit actions
- Add native Service Management controls for start at login and opt-in local
  notifications for new high-priority findings without endpoint paths
- Persist the latest report and a private operation heartbeat containing the
  scheduler state, PID, interval, last scan, and login-item state
- Add a bounded `continuous_operation` assurance sensor and teach BluePulse to
  surface stopped, stale, unsafe, or explicitly paused background monitoring
- Replace the browser-local auto-scan switch with clear native controls and add
  a reproducible continuous-operation Settings screenshot
- Keep signed in-app update metadata gated on Developer ID signing and Apple
  notarization; v0.16 continues to use manual GitHub Release replacement

## 0.15.0

- Add Persistence Atlas with independently reported coverage for login items,
  background task management, shell startup, cron, periodic jobs,
  authorization plug-ins, browser/developer extensions, profiles, privacy
  controls, and security controls
- Detect unsafe persistence ownership and permissions, symbolic links, preload
  directives, staging paths, insecure extension updates, and invalid signing
- Add bounded signing, Team ID, CDHash, Gatekeeper, and notarization context for
  privileged plug-ins and login-item apps without treating notarization as a
  runtime-safety verdict
- Keep current-user crontab commands and TCC grant rows out of reports while
  retaining privacy-safe coverage and risk summaries
- Extend integrity baselines to eligible Atlas assets and suppress false
  missing-file alerts when only one source becomes unavailable
- Add a polished Persistence view, reproducible synthetic screenshot, complete
  source/privacy reference, and cross-platform tests

## 0.14.0

- Add ReplayForge to replay strictly bounded, metadata-only endpoint fixtures
  through RATtler's production snapshot and native correlation functions
- Add Chainlight stable, time-ordered evidence chains that join events by
  process instance and rule-source links without falling back to reused PIDs
- Publish positive and negative community fixtures with expected rule IDs,
  chain counts, and performance budgets enforced in CI
- Add conservative ATT&CK context with an explicit coverage-not-verdict caveat
- Emit privacy-scrubbed investigation bundles with one-way tokens for paths,
  endpoints, and process-instance values
- Add a polished native Detection Lab view, bundle the fixtures in portable
  releases, and document a safe contribution workflow
- Add a detection proposal issue form and pull-request verification checklist
- Fix the local development engine path inside generated app bundles

## 0.13.2

- Canonicalize Windows drive and UNC paths through the filesystem before
  matching exact-identity exceptions, including short-path aliases
- Preserve absolute POSIX endpoint paths when policies are processed on Windows
- Surface compact Windows test tracebacks directly in GitHub check annotations

## 0.13.1

- Normalize reviewed-exception paths with the endpoint's native path rules so
  Deep Scan hash exceptions work consistently on Windows as well as Unix hosts

## 0.13.0

- Add a native Deep Scan tab with a file-and-folder picker and clear local-only
  content-inspection disclosure
- Bundle original community YARA rules and the YARA engine in portable macOS
  releases while keeping YARA optional for the normal Python CLI
- Calculate SHA-256, recognize Mach-O content, inspect macOS signing identity,
  and explain disguised executable and high-entropy executable traits
- Record the source filename and SHA-256 of every rule file behind a YARA match
- Give each YARA rule a source-bound identity so an exception for one rule
  cannot hide a different rule matching the same file
- Bound scans by file, byte, time, directory, finding, and output limits;
  refuse a symbolic-link target and never follow links inside a selected folder
- Connect eligible results to exact-hash reviewed exceptions and manual,
  reversible quarantine
- Add a harmless YARA validation marker, rule-contribution guidance, CLI
  documentation, and a reproducible synthetic Deep Scan screenshot

## 0.12.0

- Add reviewed, expiring finding exceptions bound to an exact rule, absolute
  path, and cryptographic code or file identity
- Refuse path-only exceptions, require a reason, cap validity at 90 days, and
  fail open with degraded coverage when a policy is invalid
- Keep linked endpoint activity visible at informational severity when its
  reviewed finding is suppressed
- Add native-app controls to create 30-day exceptions and remove them from
  Settings after confirmation
- Capture bounded process ancestry and start-time-derived process identities
- Correlate process, network, and loaded-code events by process instance to
  avoid joining unrelated processes after ordinary PID reuse
- Pin CI actions and the macOS release packager to reviewed revisions

## 0.11.0

- Record CDHash, signature kind, Team ID, and identifier for bounded
  user-writable loaded-code candidates
- Persist loaded path plus signing identity and alert when a CDHash or signer
  changes at the same path
- Explicitly identify executables running from randomized macOS App
  Translocation paths without treating translocation alone as malware
- Add CDHash to new loaded-code integrity baselines while keeping older
  baselines upgrade-compatible
- Include the acting process CDHash in native Endpoint Security JSONL events
- Keep notarization documented as distribution trust rather than a runtime
  behavior verdict

## 0.10.0

- Add an opt-in, 512 MiB Recovery Vault for versioned documents and photos
- Refresh recovery versions automatically while the app is open and freeze the
  vault when ransomware evidence appears
- Verify content-addressed objects and recover previous versions into a new
  Desktop folder without overwriting originals
- Add a separately compiled Endpoint Security ransomware guard with shadow and
  explicitly acknowledged enforcement modes
- Attribute protected-folder mutations to processes and evaluate mutation rate,
  encryption-style names, ransom notes, and canary access before a deny decision
- Surface native shadow and block decisions as explainable ransomware findings

## 0.9.0

- Add a dedicated Ransomware Defense tab to the macOS application
- Monitor bounded metadata snapshots of Desktop, Documents, and Pictures
- Detect encryption-style extension replacement, bulk rewrites, ransom-note
  creation, mass deletion, and local canary damage
- Emit explainable ransomware findings and local activity events
- Keep protected-file contents private and make automatic monitoring opt-out
- Include ransomware state and canary permissions in BluePulse assurance

## 0.8.2

- Add BluePulse detection-confidence scoring alongside threat status
- Verify available protection and behavioral sensors, event continuity, and
  local monitoring-state permissions on every scan
- Detect stale reports in the app without confusing visibility with malware
- Add a 15-second native collector heartbeat and degrade coverage when the
  stream is older than 45 seconds
- Consume heartbeat records without adding noise to the activity timeline
- Add a dedicated BluePulse interface and reproducible documentation screenshot

## 0.8.1

- Exclude RATtler's exact app and engine PIDs from process, socket, event, and
  loaded-image findings without trusting a process name
- Show a clear in-app reminder when RATtler is running outside Applications
- Put download, installation, Gatekeeper, first-scan, and removal instructions
  at the top of the README
- Rename release downloads to plain Apple Silicon and Intel labels

## 0.8.0

- Add reviewed, reversible file quarantine to the CLI and native macOS app
- Require an exact SHA-256 from a dry run before applying a quarantine action
- Refuse symbolic links, hard links, non-regular files, protected OS paths,
  changed targets, destination collisions, and cross-filesystem moves
- Remove execute permissions while retaining the payload, manifest, original
  mode and path, operator reason, and append-oriented local audit events
- Add integrity-checked restore and quarantine inventory commands
- Add response controls to eligible findings with a native confirmation dialog
- Document the staged prevention, tamper-resistance, and fleet-response roadmap

## 0.7.0

- Add a native macOS Community Preview application with a polished local UI
- Add Dashboard, Findings, Sensor Health, Activity, and Settings views
- Add one-click scanning, report export, automatic refresh, and baseline controls
- Bundle the Python detector into portable Intel and Apple Silicon release builds
- Add ad-hoc signed ZIP packaging with SHA-256 checksums
- Add tag-driven GitHub preview releases and macOS app compilation in CI
- Keep the interface local with a restrictive WebKit content-security policy

## 0.6.0

- Add a notification-only native macOS Endpoint Security collector
- Capture process, memory, task-port, tracing, remote-thread, and code-signature events
- Detect writable-executable memory and executable mappings from staging paths
- Correlate task-port access followed by cross-process thread creation
- Surface Endpoint Security sequence gaps as explicit coverage findings
- Add rotation-aware, permission-restricted native JSONL cursor ingestion
- Propagate degraded and unhealthy sensor coverage into the overall assessment
- Compile the native sensor in macOS CI without requiring production entitlements

## 0.5.1

- Add a self-cleaning, loopback-only macOS validation canary
- Document safe end-to-end detection testing
- Recognize both macOS spellings of per-user temporary directories

## 0.5.0

- Persist process, TCP socket, launchd, and loaded-image snapshots
- Emit process, listener, connection, persistence, and module-change events
- Correlate related events across a configurable 15-minute window
- Detect staged processes that establish network connections or persistence
- Detect newly loaded user-writable code followed by network activity
- Add private JSONL evidence journals with size-bounded rotation
- Keep initial state creation quiet to avoid first-run event floods

## 0.4.0

- Create permission-restricted, atomic SHA-256 integrity baselines
- Track launchd plists, startup executables, and active user-writable Mach-O code
- Detect missing, modified, replaced, and newly introduced baseline assets
- Compare content, ownership, mode, size, and symbolic-link targets
- Integrate baseline drift into normal risk scoring and watch-mode output

## 0.3.0

- Inventory file-backed executable mappings in eligible macOS processes
- Detect deleted Mach-O images retained in protected processes
- Verify modules loaded from user-writable paths with native code signing
- Compare module and host Team IDs to identify unexpected cross-vendor injection
- Exclude interpreters and data-only mappings to reduce false positives

## 0.2.0

- Add behavioral assessment and risk-ranked findings
- Detect processes executing from common staging locations
- Inspect macOS launchd persistence safely with `plistlib`
- Detect launch-time `DYLD_INSERT_LIBRARIES` and `LD_PRELOAD` injection
- Correlate externally reachable TCP listeners with process executables
- Suppress protected macOS system services and duplicate listener records

## 0.1.0

- Add antivirus health providers for macOS, Windows, and ClamAV systems
- Add one-shot and change-aware watch modes with structured JSON output
