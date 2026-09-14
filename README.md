# RATtler

RATtler is an open-source, read-only anti-RAT endpoint monitor. It combines native
antivirus health with explainable behavioral checks for suspicious process
locations, launchd persistence and preload injection, and exposed TCP listeners.
RATtler does not upload endpoint data.

Supported checks:

- Windows: Microsoft Defender antivirus, real-time protection, and signatures
- macOS: Gatekeeper and installed XProtect package metadata
- Linux/other Unix: ClamAV engine availability and `clamd` process state

Behavioral sensors in the current macOS-first build:

- Processes running from temporary, download, cache, or deleted locations
- LaunchAgents and LaunchDaemons using risky, relative, missing, or world-writable executables
- `DYLD_INSERT_LIBRARIES` and `LD_PRELOAD` configured through launchd persistence
- TCP services listening on every interface, correlated to their process path

Findings are indicators for review, not malware verdicts. RATtler never kills a
process, deletes a file, or changes a persistence entry.

## Quick start

Python 3.9 or newer is required.

```sh
python3 -m pip install -e .
rattler --pretty
rattler --watch --interval 30 --changes-only
```

Without installing:

```sh
PYTHONPATH=src python3 -m rattler --pretty
```

Every report contains endpoint-protection state, sensor coverage, risk-ranked
findings, and an overall status. One-shot exit codes are `0` healthy, `1`
degraded, `2` unknown, and `3` unhealthy. `Ctrl-C` returns `130` in watch mode.

RATtler executes only fixed command argument lists, never a shell, and has no
network code. Run it as a normal user; do not grant administrator/root privileges.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The provider boundary in `src/rattler/providers.py` is deliberately small. New
endpoint products can implement `Provider.checks()` and return normalized
`Check` values. Please avoid collecting usernames, process arguments, file paths,
or file contents in providers.

## Project status

This is an alpha anti-RAT foundation, not a replacement for antivirus/EDR. The
behavioral sensors are macOS-first; Windows and Linux currently receive antivirus
health plus the portable process/listener checks. RATtler does not yet inspect
live process memory, loaded modules, or kernel telemetry, so it cannot rule out
in-memory injection. Validate it against the endpoint images you operate before
alerting on it.

Contributions are welcome under the MIT license. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).
