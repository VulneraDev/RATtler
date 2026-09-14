# Detection Lab

ReplayForge makes RATtler detections reproducible without distributing malware.
It reads bounded JSON metadata fixtures and sends their events through the same
correlation functions used by endpoint monitoring. It never executes a fixture,
launches a process, or decodes program content.

Chainlight connects events by stable process identity and rule-source links. It
produces a time-ordered chain with stable event, chain, and rule IDs. ATT&CK
techniques are added only where the available evidence supports a specific
mapping; they are coverage context, not a malware verdict or quality score.

## Run the suite

```sh
rattler lab --pretty suite detections/fixtures
rattler lab --pretty replay detections/fixtures/staged-network-persistence.json
rattler lab --pretty bundle detections/fixtures/staged-network-persistence.json
```

Exit code `0` means every expected rule, chain count, and runtime budget passed.
Exit code `1` means a valid fixture exposed a regression. Exit code `2` means the
fixture itself was refused.

The `bundle` command emits only the privacy-scrubbed Chainlight investigation
bundle. Paths, endpoints, and process-instance values are replaced by stable
one-way tokens. The full replay output retains synthetic fixture evidence for
debugging.

## Fixture contract

Use the versioned examples in [`detections/fixtures`](../detections/fixtures).
Each fixture declares:

- schema version, lowercase stable ID, title, description, and the exact safety
  label `synthetic-no-executable-content`;
- a 1–3,600 second correlation window;
- time-ordered events with a unique stable ID, supported event type, severity,
  timezone-aware timestamp, and bounded evidence object; and
- expected rule IDs, Chainlight chain count, and maximum replay time.

ReplayForge caps a suite at 64 fixtures and each fixture at 1 MiB, 500 events, 32 KiB per evidence object,
five nested levels, and 4,096 characters per string. Symbolic-link fixtures are
refused. Process-scoped events require `process_instance`, so a reused PID cannot
silently join unrelated activity.

Keys that could contain executable or payload content are refused. Fixtures
must contain metadata only: do not include binaries, scripts, commands,
credentials, private endpoint records, encoded payloads, or live malware.

## Contribute a detection fixture

1. Start with the closest fixture and give every event a descriptive stable ID.
2. Add the smallest metadata sequence that proves the intended behavior.
3. Add or update a nearby negative fixture that must remain quiet.
4. Set expected rule IDs, chain count, and a realistic performance budget.
5. Run the full suite and unit tests before opening a pull request.

```sh
rattler lab suite detections/fixtures
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

A fixture is a detection contract. Reviewers should reject broad mappings,
unstable identifiers, unexplained false-positive tradeoffs, and tests that only
prove an alert exists without proving nearby normal activity stays quiet.
