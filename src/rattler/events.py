"""Persistent event snapshots, journaling, and behavioral correlation."""

import json
import os
import platform
import plistlib
import tempfile
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .baseline import _launchd_assets, fingerprint
from .behavior import parse_processes, suspicious_location
from .injection import _plausible_code_path, _user_writable_location, is_macho, parse_loaded_images
from .model import Check, Event, Finding, Severity, Status
from .runner import run


SCHEMA_VERSION = 1
MAX_STATE_BYTES = 32 * 1024 * 1024
DEFAULT_JOURNAL_BYTES = 10 * 1024 * 1024
MAX_RECENT_EVENTS = 5000
IGNORED_PROCESS_NAMES = {"ps", "lsof", "codesign"}


@dataclass(frozen=True)
class SocketInfo:
    pid: int
    process: str
    endpoint: str
    state: str


def parse_sockets(output: str) -> List[SocketInfo]:
    sockets = []
    seen = set()
    pid = None
    process = "unknown"
    endpoint = None
    state = None

    def finish() -> None:
        if pid is None or not endpoint or not state:
            return
        item = SocketInfo(pid, process, endpoint, state)
        if item not in seen:
            sockets.append(item)
            seen.add(item)

    for line in output.splitlines():
        if line.startswith(("p", "f")):
            finish()
            endpoint = None
            state = None
        if line.startswith("p") and line[1:].isdigit():
            pid = int(line[1:])
            process = "unknown"
        elif line.startswith("c"):
            process = line[1:]
        elif line.startswith("n"):
            endpoint = line[1:]
        elif line.startswith("TST="):
            state = line[4:]
    finish()
    return sockets


def _process_snapshot() -> Dict[str, Dict[str, object]]:
    command = ["/bin/ps", "-axo", "pid=,ppid=,comm="] if platform.system() == "Darwin" else ["ps", "-axo", "pid=,ppid=,comm="]
    result = run(command)
    if result is None or result.returncode != 0:
        return {}
    snapshot = {}
    own_pid = os.getpid()
    for process in parse_processes(result.stdout):
        if process.pid == own_pid or os.path.basename(process.executable) in IGNORED_PROCESS_NAMES:
            continue
        snapshot[str(process.pid)] = {
            "ppid": process.ppid,
            "executable": process.executable,
            "risk_reason": suspicious_location(process.executable),
        }
    return snapshot


def _socket_snapshot() -> Dict[str, Dict[str, object]]:
    lsof = "/usr/sbin/lsof" if platform.system() == "Darwin" else "lsof"
    result = run([lsof, "-nP", "-FpcnT", "-iTCP"], timeout=15.0)
    if result is None or result.returncode not in (0, 1):
        return {}
    snapshot = {}
    for item in parse_sockets(result.stdout):
        if item.state not in ("LISTEN", "ESTABLISHED"):
            continue
        key = "%s|%s|%s" % (item.pid, item.state, item.endpoint)
        snapshot[key] = {
            "pid": item.pid, "process": item.process,
            "endpoint": item.endpoint, "state": item.state,
        }
    return snapshot


def _plist_program(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    program = data.get("Program")
    if isinstance(program, str):
        return program
    arguments = data.get("ProgramArguments")
    return arguments[0] if isinstance(arguments, list) and arguments and isinstance(arguments[0], str) else None


def _persistence_snapshot() -> Dict[str, Dict[str, object]]:
    snapshot = {}
    for asset in _launchd_assets():
        if asset.kind != "launchd_plist":
            continue
        entry = fingerprint(asset)
        if entry:
            snapshot[asset.path] = {"sha256": entry.sha256, "executable": _plist_program(asset.path)}
    return snapshot


def _image_snapshot() -> Dict[str, Dict[str, object]]:
    if platform.system() != "Darwin":
        return {}
    result = run(["/usr/sbin/lsof", "-nP", "-Fpcftn", "-d", "txt"], timeout=15.0)
    if result is None or result.returncode not in (0, 1):
        return {}
    snapshot = {}
    for image in parse_loaded_images(result.stdout):
        path = image.path[:-10] if image.path.endswith(" (deleted)") else image.path
        if not _user_writable_location(path, None):
            continue
        reason = suspicious_location(path)
        if not _plausible_code_path(path, reason) or not is_macho(path):
            continue
        key = "%s|%s" % (image.pid, path)
        snapshot[key] = {"pid": image.pid, "process": image.process, "path": path}
    return snapshot


def capture_snapshot() -> Dict[str, object]:
    return {
        "processes": _process_snapshot(),
        "sockets": _socket_snapshot(),
        "persistence": _persistence_snapshot(),
        "images": _image_snapshot(),
    }


def _event(event_type: str, severity: Severity, evidence: Dict[str, object], observed_at: str) -> Event:
    return Event(str(uuid.uuid4()), event_type, severity, observed_at, evidence)


def diff_snapshots(old: Dict[str, object], new: Dict[str, object], observed_at: str) -> List[Event]:
    events = []
    old_processes = old.get("processes", {}) if isinstance(old.get("processes"), dict) else {}
    for pid, process in new.get("processes", {}).items():
        if old_processes.get(pid) == process:
            continue
        evidence = {"pid": int(pid), **process}
        severity = Severity.MEDIUM if process.get("risk_reason") else Severity.INFO
        events.append(_event("process_started", severity, evidence, observed_at))

    old_sockets = old.get("sockets", {}) if isinstance(old.get("sockets"), dict) else {}
    for key, socket in new.get("sockets", {}).items():
        if key in old_sockets:
            continue
        event_type = "listener_opened" if socket.get("state") == "LISTEN" else "connection_established"
        events.append(_event(event_type, Severity.INFO, dict(socket), observed_at))

    old_persistence = old.get("persistence", {}) if isinstance(old.get("persistence"), dict) else {}
    for path, item in new.get("persistence", {}).items():
        previous = old_persistence.get(path)
        if previous == item:
            continue
        event_type = "persistence_added" if previous is None else "persistence_changed"
        evidence = {"path": path, **item}
        events.append(_event(event_type, Severity.HIGH, evidence, observed_at))

    old_images = old.get("images", {}) if isinstance(old.get("images"), dict) else {}
    for key, image in new.get("images", {}).items():
        if key not in old_images:
            events.append(_event("loaded_image_added", Severity.INFO, dict(image), observed_at))
    return events


def correlate(events: List[Event], current_ids: set, observed_at: str) -> Tuple[List[Finding], List[Event]]:
    by_pid: Dict[int, List[Event]] = {}
    persistence = []
    for event in events:
        pid = event.evidence.get("pid")
        if isinstance(pid, int):
            by_pid.setdefault(pid, []).append(event)
        if event.event_type in ("persistence_added", "persistence_changed"):
            persistence.append(event)
    findings = []
    derived = []
    for pid, items in by_pid.items():
        kinds = {item.event_type for item in items}
        relevant = any(item.event_id in current_ids for item in items)
        if not relevant:
            continue
        risky_processes = [item for item in items if item.event_type == "process_started" and item.evidence.get("risk_reason")]
        connections = [item for item in items if item.event_type == "connection_established"]
        images = [item for item in items if item.event_type == "loaded_image_added"]
        if risky_processes and connections:
            evidence = {
                "pid": pid,
                "executable": risky_processes[-1].evidence.get("executable"),
                "remote_endpoints": sorted({item.evidence.get("endpoint") for item in connections}),
                "source_events": [item.event_id for item in risky_processes[-1:] + connections],
            }
            findings.append(Finding(
                "RAT-CORR-001", "Staged process established a network connection", Severity.CRITICAL,
                "correlation", "A process launched from a risky location and then opened a TCP connection.", evidence,
            ))
            derived.append(_event("critical_correlation", Severity.CRITICAL, {"rule_id": "RAT-CORR-001", **evidence}, observed_at))
        if images and connections:
            evidence = {
                "pid": pid,
                "images": sorted({item.evidence.get("path") for item in images}),
                "remote_endpoints": sorted({item.evidence.get("endpoint") for item in connections}),
                "source_events": [item.event_id for item in images + connections],
            }
            findings.append(Finding(
                "RAT-CORR-002", "New loaded code followed by network activity", Severity.HIGH,
                "correlation", "A process mapped user-writable Mach-O code and has a new TCP connection.", evidence,
            ))
            derived.append(_event("high_correlation", Severity.HIGH, {"rule_id": "RAT-CORR-002", **evidence}, observed_at))
        for process_event in risky_processes:
            executable = process_event.evidence.get("executable")
            matching = [item for item in persistence if item.evidence.get("executable") == executable]
            if not matching:
                continue
            evidence = {
                "pid": pid, "executable": executable,
                "persistence": [item.evidence.get("path") for item in matching],
                "source_events": [process_event.event_id] + [item.event_id for item in matching],
            }
            findings.append(Finding(
                "RAT-CORR-003", "Staged process established persistence", Severity.CRITICAL,
                "correlation", "A risky executable was added to an autostart entry.", evidence,
            ))
            derived.append(_event("critical_correlation", Severity.CRITICAL, {"rule_id": "RAT-CORR-003", **evidence}, observed_at))
    return findings, derived


def _load_state(path: Path) -> Optional[Dict[str, object]]:
    if not path.exists():
        return None
    if path.stat().st_size > MAX_STATE_BYTES:
        raise ValueError("event state exceeds size limit")
    with path.open(encoding="utf-8") as handle:
        state = json.load(handle)
    if not isinstance(state, dict) or state.get("schema") != SCHEMA_VERSION:
        raise ValueError("unsupported event-state schema")
    return state


def _write_state(path: Path, snapshot: Dict[str, object], recent: List[Event]) -> None:
    destination = path.expanduser().resolve()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    document = {"schema": SCHEMA_VERSION, "snapshot": snapshot, "recent_events": [asdict(item) for item in recent]}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(destination.parent),
            prefix=".rattler-state-", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(handle.name, 0o600)
            json.dump(document, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(destination))
        os.chmod(str(destination), 0o600)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def _append_journal(path: Path, events: List[Event], max_bytes: int) -> None:
    if not events:
        return
    destination = path.expanduser().resolve()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = "".join(json.dumps(asdict(event), sort_keys=True) + "\n" for event in events)
    if destination.exists() and destination.stat().st_size + len(payload.encode("utf-8")) > max_bytes:
        backup = destination.with_name(destination.name + ".1")
        os.replace(str(destination), str(backup))
        os.chmod(str(backup), 0o600)
    descriptor = os.open(str(destination), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(str(destination), 0o600)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def update_events(
    state_path: Path,
    journal_path: Optional[Path] = None,
    window_seconds: int = 900,
    journal_max_bytes: int = DEFAULT_JOURNAL_BYTES,
) -> Tuple[Check, List[Event], List[Finding]]:
    observed = datetime.now(timezone.utc)
    observed_at = observed.isoformat()
    try:
        previous = _load_state(state_path)
        current = capture_snapshot()
        if previous is None:
            _write_state(state_path, current, [])
            return Check("events", Status.HEALTHY, "event state initialized", {"events": 0}), [], []
        raw_recent = previous.get("recent_events", [])
        recent = [
            Event(
                event_id=item["event_id"],
                event_type=item["event_type"],
                severity=Severity(item["severity"]),
                observed_at=item["observed_at"],
                evidence=item.get("evidence", {}),
            )
            for item in raw_recent if isinstance(item, dict)
        ]
        cutoff = observed - timedelta(seconds=window_seconds)
        recent = [item for item in recent if datetime.fromisoformat(item.observed_at) >= cutoff]
        events = diff_snapshots(previous.get("snapshot", {}), current, observed_at)
        current_ids = {item.event_id for item in events}
        findings, derived = correlate(recent + events, current_ids, observed_at)
        journal_events = events + derived
        if journal_path:
            _append_journal(journal_path, journal_events, journal_max_bytes)
        _write_state(state_path, current, (recent + events)[-MAX_RECENT_EVENTS:])
        return (
            Check("events", Status.HEALTHY, "event changes correlated", {"events": len(events), "correlations": len(findings)}),
            journal_events,
            findings,
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        return Check("events", Status.UNKNOWN, "event state unavailable", {"error": str(error)}), [], []
