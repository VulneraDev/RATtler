import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional, Sequence

from .assessment import build_assessment
from .baseline import check_baseline, create_baseline
from .behavior import scan_behavior
from .events import update_events
from .model import Assessment, BehaviorReport, Status
from .providers import select_provider


EXIT_CODES = {
    Status.HEALTHY: 0,
    Status.DEGRADED: 1,
    Status.UNKNOWN: 2,
    Status.UNHEALTHY: 3,
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rattler",
        description="Read-only anti-RAT and endpoint protection watcher.",
    )
    parser.add_argument("--watch", action="store_true", help="run until interrupted")
    parser.add_argument("--interval", type=float, default=60.0, help="seconds between checks")
    parser.add_argument("--changes-only", action="store_true", help="in watch mode, emit only changes")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument("--create-baseline", metavar="PATH", help="write a known-good integrity baseline")
    baseline.add_argument("--baseline", metavar="PATH", help="check an existing integrity baseline")
    parser.add_argument("--state", metavar="PATH", help="persist snapshots for event correlation")
    parser.add_argument("--journal", metavar="PATH", help="append events as permission-restricted JSONL")
    parser.add_argument("--journal-max-bytes", type=int, default=10485760, help="rotate journal above this size")
    parser.add_argument("--event-window", type=int, default=900, help="correlation window in seconds")
    return parser


def _emit(report: Assessment, pretty: bool) -> None:
    print(json.dumps(report.to_dict(), indent=2 if pretty else None, sort_keys=True), flush=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.interval <= 0:
        _parser().error("--interval must be greater than zero")
    if args.event_window <= 0:
        _parser().error("--event-window must be greater than zero")
    if args.journal_max_bytes <= 0:
        _parser().error("--journal-max-bytes must be greater than zero")
    if args.journal and not args.state:
        _parser().error("--journal requires --state")
    if args.create_baseline:
        if args.watch:
            _parser().error("--create-baseline cannot be combined with --watch")
        try:
            summary = create_baseline(Path(args.create_baseline))
        except (OSError, ValueError) as error:
            print(json.dumps({"error": "could not create baseline", "detail": str(error)}), file=sys.stderr)
            return 2
        print(json.dumps(summary, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    provider = select_provider()
    previous = None
    try:
        while True:
            behavior = scan_behavior()
            if args.baseline:
                baseline_check, baseline_findings = check_baseline(Path(args.baseline))
                behavior = BehaviorReport(
                    sensors=behavior.sensors + [baseline_check],
                    findings=behavior.findings + baseline_findings,
                    events=behavior.events,
                )
            if args.state:
                event_check, events, event_findings = update_events(
                    Path(args.state), Path(args.journal) if args.journal else None,
                    args.event_window,
                    args.journal_max_bytes,
                )
                behavior = BehaviorReport(
                    sensors=behavior.sensors + [event_check],
                    findings=behavior.findings + event_findings,
                    events=behavior.events + events,
                )
            report = build_assessment(provider, behavior)
            fingerprint = json.dumps(
                {
                    "status": report.status,
                    "protection": report.to_dict()["protection"]["checks"],
                    "behavior": report.to_dict()["behavior"],
                },
                sort_keys=True,
            )
            if not args.changes_only or fingerprint != previous:
                _emit(report, args.pretty)
            previous = fingerprint
            if not args.watch:
                return EXIT_CODES[report.status]
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
