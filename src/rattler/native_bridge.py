"""Ingest and analyze JSONL emitted by the native macOS ES sensor."""

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .behavior import suspicious_location
from .events import MAX_RECENT_EVENTS, _append_journal
from .model import Check, Event, Finding, Severity, Status


SCHEMA_VERSION = 1
MAX_CURSOR_BYTES = 16 * 1024 * 1024
MAX_READ_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
HEARTBEAT_STALE_SECONDS = 45
ALLOWED_EVENTS = {
    "exec", "fork", "exit", "mmap", "mprotect", "get_task",
    "get_task_read", "get_task_inspect", "trace",
    "remote_thread_create", "cs_invalidated", "heartbeat",
    "ransomware_guard",
}


def _observed_at(raw: Dict[str, object]) -> str:
    nanoseconds = raw.get("timestamp_ns")
    if type(nanoseconds) is not int or nanoseconds < 0:
        raise ValueError("invalid native event timestamp")
    try:
        return datetime.fromtimestamp(nanoseconds / 1_000_000_000, tz=timezone.utc).isoformat()
    except (OSError, OverflowError):
        raise ValueError("invalid native event timestamp") from None


def translate_native_event(raw: Dict[str, object], identity: str) -> Tuple[Event, List[Finding]]:
    if raw.get("schema") != 1 or raw.get("sensor") != "rattler-es":
        raise ValueError("unsupported native event schema")
    event_type = raw.get("event_type")
    if event_type not in ALLOWED_EVENTS:
        raise ValueError("unsupported native event type")
    if type(raw.get("pid")) is not int or raw["pid"] < 0 or not isinstance(raw.get("path"), str):
        raise ValueError("native event is missing process identity")
    observed_at = _observed_at(raw)
    evidence = {
        key: value for key, value in raw.items()
        if key not in {"schema", "sensor", "timestamp_ns", "event_type"}
    }
    severity = Severity.INFO
    findings = []
    if raw.get("dropped_since_previous", 0):
        findings.append(Finding(
            "RAT-NATIVE-000", "Native sensor events were dropped", Severity.MEDIUM,
            "coverage", "The Endpoint Security client sequence contains a gap.",
            {"dropped": raw.get("dropped_since_previous"), "global_sequence": raw.get("global_sequence")},
        ))
    if event_type == "cs_invalidated":
        severity = Severity.CRITICAL
        findings.append(Finding(
            "RAT-NATIVE-001", "Running process code signature invalidated", Severity.CRITICAL,
            "injection", "macOS invalidated the code-signing state of a running process.", evidence,
        ))
    elif event_type == "mprotect":
        protection = raw.get("protection", 0)
        if isinstance(protection, int) and protection & 0x2 and protection & 0x4:
            severity = Severity.HIGH
            findings.append(Finding(
                "RAT-NATIVE-002", "Memory changed to writable and executable", Severity.HIGH,
                "injection", "A process requested simultaneous write and execute permissions for memory.", evidence,
            ))
    elif event_type == "mmap":
        protection = raw.get("protection", 0)
        source = raw.get("source_path")
        reason = suspicious_location(source) if isinstance(source, str) else None
        if isinstance(protection, int) and protection & 0x4 and reason:
            severity = Severity.HIGH
            evidence["location_reason"] = reason
            findings.append(Finding(
                "RAT-NATIVE-003", "Executable mapping loaded from a staging location", Severity.HIGH,
                "injection", "A process mapped executable pages from a risky filesystem location.", evidence,
            ))
    elif event_type == "remote_thread_create":
        severity = Severity.HIGH
        findings.append(Finding(
            "RAT-NATIVE-004", "Cross-process thread creation observed", Severity.HIGH,
            "injection", "One process created a thread in another process.", evidence,
        ))
    elif event_type == "trace":
        severity = Severity.HIGH
        findings.append(Finding(
            "RAT-NATIVE-005", "Process tracing or debugger attachment observed", Severity.HIGH,
            "injection", "One process attempted to trace or attach to another process.", evidence,
        ))
    elif event_type == "ransomware_guard":
        if raw.get("blocked") is True:
            severity = Severity.CRITICAL
            findings.append(Finding(
                "RAT-RANSOM-101", "Native guard blocked destructive file activity", Severity.CRITICAL,
                "ransomware", "The Endpoint Security guard denied another protected-folder mutation.", evidence,
            ))
        elif raw.get("would_block") is True:
            severity = Severity.HIGH
            findings.append(Finding(
                "RAT-RANSOM-100", "Native guard shadow policy crossed its threshold", Severity.HIGH,
                "ransomware", "The guard would have blocked this mutation if enforcement were enabled.", evidence,
            ))
    return Event(identity, "native_" + str(event_type), severity, observed_at, evidence), findings


def correlate_native(events: List[Event], current_ids: set, observed_at: str) -> Tuple[List[Finding], List[Event]]:
    task_events = {}
    remote_events = {}
    for event in events:
        actor = event.evidence.get("pid")
        target = event.evidence.get("target_pid")
        if not isinstance(actor, int) or not isinstance(target, int):
            continue
        key = (actor, target)
        if event.event_type in ("native_get_task", "native_get_task_read", "native_get_task_inspect"):
            task_events.setdefault(key, []).append(event)
        elif event.event_type == "native_remote_thread_create":
            remote_events.setdefault(key, []).append(event)
    findings = []
    derived = []
    for key in sorted(set(task_events).intersection(remote_events)):
        source = task_events[key] + remote_events[key]
        if not any(item.event_id in current_ids for item in source):
            continue
        actor, target = key
        evidence = {
            "actor_pid": actor,
            "target_pid": target,
            "actor_path": source[-1].evidence.get("path"),
            "target_path": source[-1].evidence.get("target_path"),
            "source_events": [item.event_id for item in source],
        }
        findings.append(Finding(
            "RAT-NATIVE-006", "Task-port access followed by remote thread creation",
            Severity.CRITICAL, "injection",
            "A process obtained access to another task and created a thread inside it.", evidence,
        ))
        event_id = hashlib.sha256(
            ("RAT-NATIVE-006:" + ":".join(str(value) for value in key) + ":" + observed_at).encode()
        ).hexdigest()
        derived.append(Event(event_id, "native_critical_correlation", Severity.CRITICAL, observed_at,
                             {"rule_id": "RAT-NATIVE-006", **evidence}))
    return findings, derived


def _load_cursor(path: Path) -> Optional[Dict[str, object]]:
    if not path.exists():
        return None
    if path.stat().st_size > MAX_CURSOR_BYTES:
        raise ValueError("native cursor exceeds size limit")
    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or document.get("schema") != SCHEMA_VERSION:
        raise ValueError("unsupported native cursor schema")
    return document


def _write_cursor(path: Path, device: int, inode: int, offset: int, recent: List[Event]) -> None:
    destination = path.expanduser().absolute()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    document = {
        "schema": SCHEMA_VERSION,
        "device": device,
        "inode": inode,
        "offset": offset,
        "recent_events": [asdict(item) for item in recent[-MAX_RECENT_EVENTS:]],
    }
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(destination.parent),
            prefix=".rattler-native-cursor-", delete=False,
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


def _deserialize_events(items: object) -> List[Event]:
    if not isinstance(items, list):
        raise ValueError("invalid native recent-event list")
    events = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("invalid native recent event")
        evidence = item.get("evidence", {})
        if (
            not isinstance(item.get("event_id"), str)
            or not isinstance(item.get("event_type"), str)
            or not isinstance(item.get("observed_at"), str)
            or not isinstance(evidence, dict)
        ):
            raise ValueError("invalid native recent event")
        events.append(Event(
            event_id=item["event_id"], event_type=item["event_type"],
            severity=Severity(item.get("severity")), observed_at=item["observed_at"],
            evidence=evidence,
        ))
    return events


def ingest_native_events(
    event_path: Path,
    cursor_path: Path,
    journal_path: Optional[Path] = None,
    window_seconds: int = 900,
    journal_max_bytes: int = 10 * 1024 * 1024,
) -> Tuple[Check, List[Event], List[Finding]]:
    try:
        source = event_path.expanduser().absolute()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(source), flags)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("native event stream must be a regular file")
            cursor = _load_cursor(cursor_path)
            heartbeat_age = max(0.0, datetime.now(timezone.utc).timestamp() - metadata.st_mtime)
            if cursor is None:
                _write_cursor(cursor_path, metadata.st_dev, metadata.st_ino, metadata.st_size, [])
                heartbeat_stale = heartbeat_age > HEARTBEAT_STALE_SECONDS
                return Check(
                    "native_events",
                    Status.DEGRADED if heartbeat_stale else Status.HEALTHY,
                    "native sensor heartbeat is stale" if heartbeat_stale else "native event cursor initialized",
                    {"events": 0, "heartbeats": 0, "heartbeat_age_seconds": round(heartbeat_age, 1)},
                ), [], []
            offset = int(cursor.get("offset", 0))
            if cursor.get("device") != metadata.st_dev or cursor.get("inode") != metadata.st_ino or metadata.st_size < offset:
                offset = 0
            handle.seek(offset)
            payload = handle.read(MAX_READ_BYTES)
            final_size = os.fstat(handle.fileno()).st_size
        newline = payload.rfind(b"\n")
        if newline < 0:
            complete = payload if len(payload) == MAX_READ_BYTES else b""
        else:
            complete = payload[:newline + 1]
        next_offset = offset + len(complete)
        events = []
        findings = []
        malformed = 0
        heartbeats = 0
        position = offset
        for line in complete.splitlines(keepends=True):
            raw_line = line.rstrip(b"\r\n")
            identity = hashlib.sha256(
                ("%s:%s:" % (metadata.st_ino, position)).encode() + raw_line
            ).hexdigest()
            position += len(line)
            if not raw_line or len(raw_line) > MAX_LINE_BYTES:
                malformed += 1
                continue
            try:
                raw = json.loads(raw_line)
                if not isinstance(raw, dict):
                    raise ValueError("event is not an object")
                event, direct = translate_native_event(raw, identity)
                if event.event_type == "native_heartbeat":
                    heartbeats += 1
                    continue
                events.append(event)
                findings.extend(direct)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, OverflowError):
                malformed += 1
        recent = _deserialize_events(cursor.get("recent_events", []))
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_seconds)
        recent = [item for item in recent if datetime.fromisoformat(item.observed_at) >= cutoff]
        current_ids = {item.event_id for item in events}
        correlations, derived = correlate_native(recent + events, current_ids, now.isoformat())
        findings.extend(correlations)
        emitted = events + derived
        if journal_path:
            _append_journal(journal_path, emitted, journal_max_bytes)
        _write_cursor(cursor_path, metadata.st_dev, metadata.st_ino, next_offset, recent + events)
        remaining = max(0, final_size - next_offset)
        heartbeat_stale = heartbeat_age > HEARTBEAT_STALE_SECONDS
        sensor_status = Status.DEGRADED if malformed or remaining or heartbeat_stale else Status.HEALTHY
        return (
            Check("native_events", sensor_status,
                  "native sensor heartbeat is stale" if heartbeat_stale else "native events ingested",
                  {"events": len(events), "correlations": len(correlations), "malformed": malformed,
                   "remaining_bytes": remaining, "heartbeats": heartbeats,
                   "heartbeat_age_seconds": round(heartbeat_age, 1)}),
            emitted,
            findings,
        )
    except (OSError, ValueError, TypeError, OverflowError, json.JSONDecodeError) as error:
        return Check("native_events", Status.UNKNOWN, "native event stream unavailable", {"error": str(error)}), [], []
