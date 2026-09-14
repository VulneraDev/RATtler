# Contributing

Thank you for helping improve RATtler.

1. Open an issue describing the endpoint product, OS versions, and safe status
   fields you want to support.
2. Keep providers read-only, dependency-light, and free of personal or file-level
   telemetry.
3. Add unit tests with mocked command output; tests must not require an installed
   antivirus product or elevated privileges.
4. Run `PYTHONPATH=src python3 -m unittest discover -s tests -v`.

Security issues that could expose endpoint information should be reported
privately as described in [`SECURITY.md`](SECURITY.md), not in a public issue.
