# RATtler for macOS

RATtler Community Preview is a native AppKit application with a local WebKit
interface. It runs the open-source RATtler engine as a child process, renders
its structured report, and offers explicit local quarantine for eligible
file-backed findings without uploading endpoint data.

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
python3 -m pip install pyinstaller
./app/macos/build.sh --portable --archive
```

Portable builds bundle Python in a private engine directory and do not require
users to install RATtler or Python separately. They are ad-hoc signed, not
notarized, so macOS identifies them as community preview builds. The release
workflow builds separate Apple Silicon and Intel artifacts on GitHub-hosted
macOS runners.

## Verify a GitHub release (optional)

The `.sha256` file is not required to run RATtler. To verify a download, keep
the ZIP and its matching checksum together and run:

```sh
shasum -a 256 -c RATtler-macOS-Intel.sha256
```

Use `RATtler-macOS-Apple-Silicon.sha256` instead on an Apple-chip Mac.

The app writes mode-`0600` state, journals, baselines, and reports beneath
`~/Library/Application Support/RATtler`. Its WebKit view has a restrictive
content-security policy and never loads remote application code. A quarantine
action first computes the file's SHA-256, shows the exact path and digest in a
native confirmation, and only then repeats the request with that digest. The
engine refuses changed files and keeps a reversible local manifest and audit
trail beneath `Application Support/RATtler/quarantine`.
