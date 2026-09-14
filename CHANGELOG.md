# Changelog

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
