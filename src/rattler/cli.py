import argparse
import json
import sys
import time
from typing import Optional, Sequence

from .assessment import build_assessment
from .behavior import scan_behavior
from .model import Assessment, Status
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
    return parser


def _emit(report: Assessment, pretty: bool) -> None:
    print(json.dumps(report.to_dict(), indent=2 if pretty else None, sort_keys=True), flush=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.interval <= 0:
        _parser().error("--interval must be greater than zero")
    provider = select_provider()
    previous = None
    try:
        while True:
            report = build_assessment(provider, scan_behavior())
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
