# Contributing

Thank you for helping improve RATtler.

1. Open an issue describing the endpoint product, OS versions, and safe status
   fields you want to support.
2. Keep providers read-only, dependency-light, and free of personal or file-level
   telemetry.
3. Add unit tests with mocked command output; tests must not require an installed
   antivirus product or elevated privileges.
4. Run `PYTHONPATH=src python3 -m unittest discover -s tests -v`.

## Detection rules

Community YARA rules belong in `rules/` and must be original or license-compatible
with RATtler's MIT distribution. Every rule should include a plain-language
`description`, a supported `severity`, and a `confidence` value. Prefer two or
more related signals over a single common string, cap conditions with
`filesize`, and describe matches as evidence to review rather than malware
verdicts.

Add a harmless fixture or test that proves the intended match and a nearby
negative case when practical. Never commit live malware, credentials, weaponized
payloads, or private endpoint data. `RATtler_Safe_File_Canary` exists for testing
the full scan path without malicious behavior.

Behavioral correlation contributions must include a ReplayForge contract in
`detections/fixtures`: expected rule IDs, expected Chainlight count, a runtime
budget, and a negative fixture. Read the [Detection Lab guide](docs/DETECTION_LAB.md)
before proposing one. Fixture metadata is strictly bounded and must never carry
executable content.

Security issues that could expose endpoint information should be reported
privately as described in [`SECURITY.md`](SECURITY.md), not in a public issue.
