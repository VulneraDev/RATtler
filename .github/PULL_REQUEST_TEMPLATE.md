## What changed

Describe the user-visible behavior and why it belongs in RATtler.

## Verification

- [ ] `rattler lab suite detections/fixtures` passes
- [ ] `PYTHONPATH=src python3 -m unittest discover -s tests -v` passes
- [ ] New detection logic has a positive fixture and a nearby negative fixture
- [ ] Fixtures contain synthetic metadata only—no executable content, secrets, or private endpoint data
- [ ] Findings explain evidence and do not claim a malware verdict
- [ ] Privacy, safety limits, and platform-coverage changes are documented

## Evidence

Paste concise test output or screenshots. Do not attach live malware.
