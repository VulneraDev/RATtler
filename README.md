# RATtler

RATtler is a free, open-source anti-RAT monitor. It checks a Mac for suspicious
processes, persistence, network listeners, and loaded code. Everything stays on
the computer unless you export a report yourself.

> RATtler is a community preview, not a replacement for supported antivirus or
> EDR software. A finding means “review this,” not “this is definitely malware.”

## Download for macOS

Download **one ZIP**—not both:

- [Mac with an Apple chip](https://github.com/VulneraDev/RATtler/releases/download/v0.9.0/RATtler-macOS-Apple-Silicon.zip)
- [Mac with an Intel processor](https://github.com/VulneraDev/RATtler/releases/download/v0.9.0/RATtler-macOS-Intel.zip)

Not sure which Mac you have? Open **Apple menu → About This Mac**:

- If it says **Chip: Apple M1, M2, M3, M4, or newer**, choose Apple chip.
- If it says **Processor: Intel**, choose Intel.

The small `.sha256` downloads on the release page are optional verification
files. Most people only need the ZIP.

## Install

1. Open the downloaded ZIP.
2. Open Finder and choose **Downloads**.
3. Drag `RATtler.app` onto **Applications** in Finder’s sidebar.
4. Open **Applications** and double-click RATtler.
5. If macOS blocks it, open **System Settings → Privacy & Security**, scroll to
   **Security**, and click **Open Anyway**.
6. Enter your Mac password and click **Open**.

RATtler is not Apple-notarized yet, which is why the one-time warning appears.
Do not disable Gatekeeper globally.

## Run your first scan

RATtler scans automatically when it opens. You can also click **Scan now**.

- **Protected** means no urgent indicator was found with the available sensors.
- **Action required** means something deserves review. It is not a malware
  verdict.
- Open **Findings** to see the exact process or file path and the reason.
- Only use **Review quarantine** after you recognize and verify the exact file.

If RATtler says it is running from Downloads, close it, drag it into
**Applications**, and reopen it there. RATtler excludes its exact app and
scan-engine process IDs so it does not flag itself.

## BluePulse

BluePulse answers: **“Can I trust the sensors behind this result?”** It keeps
detection confidence separate from threat severity. A scan can therefore show
a real threat with high confidence, or no threat while warning that visibility
is incomplete.

It checks whether available protection and behavioral sensors replied, whether
the report is fresh, whether event state is continuous, whether local monitoring
files have safe permissions, and whether native telemetry reported a heartbeat
or dropped events. Optional native telemetry and integrity baselines are clearly
labeled when they are not configured; their absence is not presented as failure.

![RATtler BluePulse detection confidence](docs/images/rattler-bluepulse.png)

## Ransomware Defense

The **Ransomware** tab watches file metadata in Desktop, Documents, and Pictures
for changes commonly associated with encryption attacks. It detects bursts of
file rewrites, encryption-style extension replacements, possible ransom-note
filenames, mass deletion, and modification of a harmless local canary.

Monitoring is local, bounded to 25,000 files, and runs on each scan while
RATtler is open. RATtler does not read or upload protected-file contents. This
release detects and explains suspicious changes; it does not automatically
block writes, kill processes, or restore encrypted data.

![RATtler Ransomware Defense](docs/images/rattler-ransomware.png)

## Screenshots

These use safe synthetic data; no malware was installed to create them.

Healthy endpoint:

![RATtler showing a healthy endpoint](docs/images/rattler-healthy.png)

Risk detected:

![RATtler showing findings that need review](docs/images/rattler-risk.png)

## What RATtler checks

- Processes launched from temporary, download, cache, or deleted locations
- Suspicious LaunchAgents and LaunchDaemons
- `DYLD_INSERT_LIBRARIES` and `LD_PRELOAD` persistence
- TCP services exposed on every network interface
- Deleted or untrusted Mach-O code loaded into protected processes
- Code-signing and Team ID mismatches
- Ransomware-style bulk rewrites, extension churn, ransom notes, mass deletion,
  and local canary damage
- BluePulse sensor confidence, scan freshness, state permissions, and event loss
- Gatekeeper and XProtect health on macOS
- Microsoft Defender health on Windows
- ClamAV availability on Linux and other Unix systems
- Native memory, task-port, tracing, and remote-thread events when Apple’s
  restricted Endpoint Security entitlement is provisioned

## Quarantine and restore

Quarantine is always manual. RATtler first shows the exact path and SHA-256,
then asks for confirmation. It moves the file into private local storage and
removes execute permission; it does not delete the file or stop a process that
is already running.

Open **Settings → Response** to view or restore quarantined files. Restore checks
the file again and never overwrites an existing destination.

## Privacy and safety

- No account is required.
- The app contains no telemetry upload or remote-control service.
- Reports and response history stay in
  `~/Library/Application Support/RATtler`.
- RATtler never quarantines automatically.
- The current Endpoint Security collector is detection-only.
- Ransomware monitoring records file paths, size, modification time, and inode
  locally; it does not inspect protected-file contents.
- BluePulse is tamper-evident within the app’s current permissions; it is not a
  substitute for the planned signed system extension and root-owned state.

## Update or remove RATtler

To update, quit RATtler, download the newest ZIP, and replace the old app in
Applications.

To remove it, quit RATtler and drag it from Applications to Trash. Its local
history remains in `~/Library/Application Support/RATtler`; delete that folder
only if you also want to remove reports, baselines, and quarantined files.

## Developers

Python, CLI, baseline, event-correlation, quarantine, and safe-canary commands
are in the [CLI guide](docs/CLI.md). Build and packaging instructions are in the
[macOS app guide](app/macos/README.md). Native sensor provisioning is in the
[Endpoint Security guide](native/macos/README.md).

```sh
python3 -m pip install -e .
rattler --pretty
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

RATtler’s staged prevention, system-extension, tamper-evidence, and fleet plans
are documented in the [response roadmap](docs/ROADMAP.md).

Contributions are welcome under the MIT license. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).
