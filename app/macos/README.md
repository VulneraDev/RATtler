# RATtler for macOS

RATtler Community Preview is a native AppKit application with a local WebKit
interface. It runs the open-source RATtler engine as a child process, renders
its structured report, and offers explicit local quarantine for eligible
file-backed findings without uploading endpoint data.

The BluePulse view separates detection confidence from threat status. It shows
scan freshness, responding layers, native scheduling and pause state,
monitoring-file permission health, native collector heartbeat state, and
dropped-event evidence.

The native app owns a 60-second scheduler and menu-bar controller. Closing the
main window leaves scheduled scans running. The menu exposes reopen, scan now,
pause/resume, start-at-login, notification, and quit controls. Finding
notifications are opt-in and omit paths. A private operation heartbeat lets the
engine verify whether this controller is actually alive. See the
[continuous-operation guide](../../docs/CONTINUOUS_OPERATION.md).

Loaded-code findings include path, CDHash, signature type, and Team ID when
available. RATtler explicitly labels code running from macOS App Translocation
paths and reports identity drift at a previously observed loaded path.

The Ransomware Defense view compares bounded metadata snapshots of Desktop,
Documents, and Pictures on every scan. It surfaces rewrite bursts,
encryption-style renames, ransom-note filenames, mass deletion, and local
canary damage without reading or uploading protected-file contents. Automatic
monitoring is enabled by default and runs every 60 seconds while the native app
is running, even when its main window is closed.

Recovery Vault is optional. After native confirmation it keeps up to 512 MB of
versioned, content-addressed document and photo copies beneath Application
Support. Automatic updates freeze on ransomware evidence. Reviewed recovery
creates a new Desktop folder and never overwrites originals.

Deep Scan reads only a file or folder selected through the native picker. It
applies the bundled community YARA rules, calculates SHA-256, inspects Mach-O
signing, and returns explainable static evidence. Scanning is bounded and local;
symbolic links are not followed and no content is uploaded.

The Detection Lab runs the bundled ReplayForge positive and negative fixtures
through the production correlators. Chainlight renders stable, time-ordered
evidence and conservative ATT&CK context. Fixtures are metadata-only, bounded,
and bundled under app Resources so the same contracts run in the UI, CLI, and CI.

Persistence Atlas maps eleven independent macOS autostart and configuration
sources. The view keeps collector health, observed objects, and alert rules
separate so a normal extension or profile is not presented as malware. Source
traversal, command output, manifest reads, and signing checks are bounded;
symbolic links are never followed. See the
[source and privacy reference](../../docs/PERSISTENCE_ATLAS.md).

## Install the app

Download one ZIP from the main [README](../../README.md), open it, then drag
`RATtler.app` from Downloads into Applications. Launch it from Applications.

The preview is ad-hoc signed but not Apple-notarized. If macOS blocks the first
launch, open **System Settings → Privacy & Security**, scroll to **Security**,
click **Open Anyway**, enter your password, and click **Open**. Do not disable
Gatekeeper globally.

If RATtler is launched outside Applications, the dashboard shows a move reminder.
The app passes its exact PID to the engine, and the engine also excludes its own
PID, so neither process is treated as an endpoint finding.

Start at login uses `SMAppService.mainAppService` and may require approval in
**System Settings → General → Login Items**. Notifications use the native user
notification permission prompt. Neither feature is enabled silently.

## Development build

```sh
./app/macos/build.sh
open build/macos/RATtler.app
```

The development bundle uses the repository's Python source through
`DevelopmentEngine.sh`. It is intended only for local development and stops
working if moved away from the repository.

## Portable preview

Install the build-only dependency and create a self-contained ZIP file:

```sh
MACOSX_DEPLOYMENT_TARGET=13.0 python3 -m pip install pyinstaller
MACOSX_DEPLOYMENT_TARGET=13.0 python3 -m pip install \
  --no-binary=yara-python yara-python==4.5.4
./app/macos/build.sh --portable --archive
```

Portable builds bundle Python in a private engine directory and do not require
users to install RATtler or Python separately. They are ad-hoc signed, not
notarized, so macOS identifies them as community preview builds. The release
workflow builds separate Apple Silicon and Intel artifacts on GitHub-hosted
macOS runners.

Portable bundles include the YARA and yara-python license texts under app
Resources. See [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).

## Verify a GitHub release (optional)

The `.sha256` file is not required to run RATtler. To verify a download, keep
the ZIP and its matching checksum together and run:

```sh
shasum -a 256 -c RATtler-macOS-Intel.sha256
```

Use `RATtler-macOS-Apple-Silicon.sha256` instead on an Apple-chip Mac.

The app writes mode-`0600` state, operation heartbeat, last report, journals,
baselines, and reports beneath
`~/Library/Application Support/RATtler`. Its WebKit view has a restrictive
content-security policy and never loads remote application code. A quarantine
action first computes the file's SHA-256, shows the exact path and digest in a
native confirmation, and only then repeats the request with that digest. The
engine refuses changed files and keeps a reversible local manifest and audit
trail beneath `Application Support/RATtler/quarantine`.
