# Changelog

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
