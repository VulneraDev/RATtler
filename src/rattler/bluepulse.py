"""BluePulse assurance for RATtler's detection coverage.

BluePulse does not decide whether endpoint activity is malicious. It answers a
different question: whether the sensors and local monitoring state used for the
current report were available and internally consistent.
"""

import os
import stat
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .model import Check, Finding, Status


def _not_applicable(check: Check) -> bool:
    return check.status == Status.UNKNOWN and "-only" in check.message.lower()


def _artifact_issue(
    role: str,
    path: Path,
    *,
    private: bool,
    allow_missing: bool = False,
) -> Optional[Dict[str, str]]:
    destination = path.expanduser().absolute()
    try:
        metadata = os.lstat(str(destination))
    except FileNotFoundError:
        if allow_missing:
            return None
        return {"artifact": role, "path": str(destination), "reason": "missing"}
    except OSError as error:
        return {"artifact": role, "path": str(destination), "reason": str(error)}
    if stat.S_ISLNK(metadata.st_mode):
        return {"artifact": role, "path": str(destination), "reason": "symbolic link"}
    if not stat.S_ISREG(metadata.st_mode):
        return {"artifact": role, "path": str(destination), "reason": "not a regular file"}
    if os.name != "nt":
        mode = stat.S_IMODE(metadata.st_mode)
        forbidden = 0o077 if private else 0o022
        if mode & forbidden:
            expectation = "private" if private else "not group/world writable"
            return {
                "artifact": role,
                "path": str(destination),
                "reason": "mode %04o is not %s" % (mode, expectation),
            }
        if private and metadata.st_uid != os.geteuid():
            return {"artifact": role, "path": str(destination), "reason": "owned by another user"}
    return None


def evaluate_bluepulse(
    protection_checks: Sequence[Check],
    sensor_checks: Sequence[Check],
    findings: Sequence[Finding],
    *,
    state_path: Optional[Path] = None,
    journal_path: Optional[Path] = None,
    baseline_path: Optional[Path] = None,
    native_event_path: Optional[Path] = None,
) -> Check:
    """Return an explainable confidence check for the current scan."""
    checks = [
        check for check in list(protection_checks) + list(sensor_checks)
        if check.name != "bluepulse" and not _not_applicable(check)
    ]
    gaps = [
        {"sensor": check.name, "status": check.status.value, "message": check.message}
        for check in checks if check.status != Status.HEALTHY
    ]

    artifacts: List[Tuple[str, Path, bool, bool]] = []
    if state_path is not None:
        artifacts.append(("event state", state_path, True, False))
    if journal_path is not None:
        artifacts.append(("event journal", journal_path, True, True))
    if baseline_path is not None:
        artifacts.append(("integrity baseline", baseline_path, True, False))
    if native_event_path is not None:
        artifacts.append(("native event stream", native_event_path, False, False))
        if state_path is not None:
            artifacts.append(("native event cursor", Path(str(state_path) + ".native-cursor"), True, False))

    artifact_issues = []
    artifacts_checked = 0
    for role, path, private, allow_missing in artifacts:
        issue = _artifact_issue(role, path, private=private, allow_missing=allow_missing)
        if issue:
            artifact_issues.append(issue)
        elif path.expanduser().absolute().exists():
            artifacts_checked += 1

    dropped_events = sum(
        int(item.evidence.get("dropped", 0))
        for item in findings
        if item.rule_id == "RAT-NATIVE-000" and type(item.evidence.get("dropped")) is int
    )
    statuses = {check.status for check in checks}
    if not checks:
        pulse_status = Status.UNKNOWN
    elif Status.UNHEALTHY in statuses:
        pulse_status = Status.UNHEALTHY
    elif Status.UNKNOWN in statuses:
        pulse_status = Status.UNKNOWN
    elif Status.DEGRADED in statuses or artifact_issues or dropped_events:
        pulse_status = Status.DEGRADED
    else:
        pulse_status = Status.HEALTHY

    confidence = {
        Status.HEALTHY: "high",
        Status.DEGRADED: "reduced",
        Status.UNKNOWN: "low",
        Status.UNHEALTHY: "low",
    }[pulse_status]
    messages = {
        Status.HEALTHY: "available sensor coverage verified",
        Status.DEGRADED: "sensor assurance needs review",
        Status.UNKNOWN: "sensor confidence could not be verified",
        Status.UNHEALTHY: "a defensive layer reported unhealthy",
    }
    sensor_by_name = {check.name: check for check in sensor_checks}
    native = sensor_by_name.get("native_events")
    baseline = sensor_by_name.get("baseline")
    events = sensor_by_name.get("events")
    return Check(
        "bluepulse",
        pulse_status,
        messages[pulse_status],
        {
            "confidence": confidence,
            "confidence_scope": "available sensors",
            "operational": sum(check.status == Status.HEALTHY for check in checks),
            "monitored": len(checks),
            "coverage_gaps": gaps,
            "monitoring_mode": "continuous snapshots" if events else "one-time snapshot",
            "event_continuity": events.status.value if events else "not configured",
            "native_telemetry": native.status.value if native else "not configured",
            "native_dropped_events": dropped_events,
            "integrity_baseline": baseline.status.value if baseline else "not configured",
            "artifacts_checked": artifacts_checked,
            "artifact_issues": artifact_issues,
        },
    )
