import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional, Sequence

from .assessment import build_assessment
from .baseline import check_baseline, create_baseline
from .behavior import scan_behavior
from .bluepulse import evaluate_bluepulse
from .events import update_events
from .model import Assessment, BehaviorReport, Check, Status
from .native_bridge import ingest_native_events
from .operation import continuous_operation_sensor
from .providers import select_provider
from .ransomware import DEFAULT_MAX_FILES, scan_ransomware
from .recovery import status as recovery_status
from .suppressions import apply_exceptions


EXIT_CODES = {
    Status.HEALTHY: 0,
    Status.DEGRADED: 1,
    Status.UNKNOWN: 2,
    Status.UNHEALTHY: 3,
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rattler",
        description="Anti-RAT endpoint monitoring and explicit response tooling.",
        epilog="Use 'rattler response --help' for reversible quarantine commands.",
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
    parser.add_argument("--native-events", metavar="PATH", help="ingest native Endpoint Security JSONL")
    parser.add_argument("--operation-state", metavar="PATH", help="verify native app scheduler heartbeat")
    parser.add_argument("--ransomware-state", metavar="PATH", help="persist anti-ransomware file-change state")
    parser.add_argument(
        "--ransomware-root", metavar="PATH", action="append", default=[],
        help="folder to monitor for encryption-like changes (repeatable)",
    )
    parser.add_argument(
        "--ransomware-max-files", type=int, default=DEFAULT_MAX_FILES,
        help="maximum number of files sampled by ransomware monitoring",
    )
    parser.add_argument("--recovery-store", metavar="PATH", help="report local recovery-vault health")
    parser.add_argument(
        "--exceptions", metavar="PATH",
        help="apply narrow, expiring finding exceptions from a local policy",
    )
    parser.add_argument(
        "--exclude-pid", metavar="PID", type=int, action="append", default=[],
        help="exclude one trusted host process PID (repeatable)",
    )
    return parser


def _emit(report: Assessment, pretty: bool) -> None:
    print(json.dumps(report.to_dict(), indent=2 if pretty else None, sort_keys=True), flush=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw_arguments = list(argv) if argv is not None else sys.argv[1:]
    if raw_arguments and raw_arguments[0] == "response":
        from .response_cli import main as response_main

        return response_main(raw_arguments[1:])
    if raw_arguments and raw_arguments[0] == "recovery":
        from .recovery import main as recovery_main

        return recovery_main(raw_arguments[1:])
    if raw_arguments and raw_arguments[0] == "exceptions":
        from .suppressions import main as suppressions_main

        return suppressions_main(raw_arguments[1:])
    if raw_arguments and raw_arguments[0] == "files":
        from .file_scanner import main as file_scanner_main

        return file_scanner_main(raw_arguments[1:])
    if raw_arguments and raw_arguments[0] == "lab":
        from .detection_lab import main as detection_lab_main

        return detection_lab_main(raw_arguments[1:])
    args = _parser().parse_args(raw_arguments)
    if args.interval <= 0:
        _parser().error("--interval must be greater than zero")
    if args.event_window <= 0:
        _parser().error("--event-window must be greater than zero")
    if args.journal_max_bytes <= 0:
        _parser().error("--journal-max-bytes must be greater than zero")
    if args.ransomware_max_files <= 0:
        _parser().error("--ransomware-max-files must be greater than zero")
    if any(pid <= 0 for pid in args.exclude_pid):
        _parser().error("--exclude-pid values must be greater than zero")
    if args.journal and not args.state:
        _parser().error("--journal requires --state")
    if args.native_events and not args.state:
        _parser().error("--native-events requires --state")
    if args.ransomware_root and not args.ransomware_state:
        _parser().error("--ransomware-root requires --ransomware-state")
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
            behavior = scan_behavior(excluded_pids=args.exclude_pid)
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
                    args.exclude_pid,
                )
                behavior = BehaviorReport(
                    sensors=behavior.sensors + [event_check],
                    findings=behavior.findings + event_findings,
                    events=behavior.events + events,
                )
            if args.native_events:
                cursor_path = Path(str(args.state) + ".native-cursor")
                native_check, native_events, native_findings = ingest_native_events(
                    Path(args.native_events), cursor_path,
                    Path(args.journal) if args.journal else None,
                    args.event_window, args.journal_max_bytes,
                )
                behavior = BehaviorReport(
                    sensors=behavior.sensors + [native_check],
                    findings=behavior.findings + native_findings,
                    events=behavior.events + native_events,
                )
            if args.operation_state:
                operation_check = continuous_operation_sensor(Path(args.operation_state))
                behavior = BehaviorReport(
                    sensors=behavior.sensors + [operation_check],
                    findings=behavior.findings,
                    events=behavior.events,
                )
            if args.ransomware_state:
                ransomware_roots = [Path(item) for item in args.ransomware_root] or [
                    Path.home() / "Desktop", Path.home() / "Documents", Path.home() / "Pictures",
                ]
                ransomware_check, ransomware_findings, ransomware_events = scan_ransomware(
                    Path(args.ransomware_state), ransomware_roots, args.ransomware_max_files,
                )
                behavior = BehaviorReport(
                    sensors=behavior.sensors + [ransomware_check],
                    findings=behavior.findings + ransomware_findings,
                    events=behavior.events + ransomware_events,
                )
            if args.recovery_store:
                try:
                    recovery = recovery_status(Path(args.recovery_store))
                    recovery_check = Check(
                        "recovery_vault",
                        Status.HEALTHY if recovery.get("enabled") else Status.UNKNOWN,
                        "recovery copies available" if recovery.get("enabled") else "recovery vault is not initialized",
                        recovery,
                    )
                except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                    recovery_check = Check(
                        "recovery_vault", Status.UNKNOWN, "recovery vault unavailable", {"error": str(error)},
                    )
                behavior = BehaviorReport(
                    sensors=behavior.sensors + [recovery_check],
                    findings=behavior.findings,
                    events=behavior.events,
                )
            if args.exceptions:
                exception_check, findings, events = apply_exceptions(
                    Path(args.exceptions), behavior.findings, behavior.events,
                )
                behavior = BehaviorReport(
                    sensors=behavior.sensors + [exception_check],
                    findings=findings,
                    events=events,
                )
            protection = provider.report()
            bluepulse = evaluate_bluepulse(
                protection.checks,
                behavior.sensors,
                behavior.findings,
                state_path=Path(args.state) if args.state else None,
                journal_path=Path(args.journal) if args.journal else None,
                baseline_path=Path(args.baseline) if args.baseline else None,
                native_event_path=Path(args.native_events) if args.native_events else None,
                ransomware_state_path=Path(args.ransomware_state) if args.ransomware_state else None,
                recovery_store_path=Path(args.recovery_store) if args.recovery_store else None,
                operation_state_path=Path(args.operation_state) if args.operation_state else None,
            )
            behavior = BehaviorReport(
                sensors=behavior.sensors + [bluepulse],
                findings=behavior.findings,
                events=behavior.events,
            )
            report = build_assessment(provider, behavior, protection)
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
