# RATtler for macOS

RATtler Community Preview is a native AppKit application with a local WebKit
interface. It runs the open-source RATtler engine as a child process and renders
its structured report without uploading endpoint data.

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

## Install a GitHub release

1. Download the ZIP and matching `.sha256` file for your Mac from
   [GitHub Releases](https://github.com/VulneraDev/RATtler/releases).
2. Keep both files together and run `shasum -a 256 -c <checksum-file>`.
3. Unzip the download and move `RATtler.app` into Applications.
4. On first launch, Control-click the app and choose **Open**. This is expected
   until RATtler has an Apple Developer ID signature and notarization.

The app writes mode-`0600` state, journals, baselines, and reports beneath
`~/Library/Application Support/RATtler`. Its WebKit view has a restrictive
content-security policy and never loads remote application code.
