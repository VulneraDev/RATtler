"""Assurance for the macOS FSEvents protected-folder trigger."""

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .model import Check, Status
from .operation import _process_alive, _timestamp


MAX_STATE_BYTES = 64 * 1024
MAX_HEARTBEAT_AGE_SECONDS = 180
STATE_FIELDS = {
    "schema", "pid", "updated_at", "started_at", "stream_active",
    "roots_watched", "latency_seconds", "events_seen", "triggered_scans",
    "dropped_events_total", "unreconciled_drop", "last_event_id",
    "last_event_at", "path_data_retained",
}


def native_file_event_sensor(path: Path, now: Optional[datetime] = None) -> Check:
    destination = path.expanduser().absolute()
    try:
        metadata = os.lstat(str(destination))
    except OSError as error:
        return Check("native_file_events", Status.UNKNOWN, "file-event stream state unavailable", {"error": str(error)})
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return Check("native_file_events", Status.DEGRADED, "file-event state is not a safe regular file")
    if metadata.st_size > MAX_STATE_BYTES:
        return Check("native_file_events", Status.DEGRADED, "file-event state exceeded its size limit")
    if os.name != "nt":
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & 0o077 or metadata.st_uid != os.geteuid():
            return Check(
                "native_file_events", Status.DEGRADED,
                "file-event state permissions need review", {"mode": format(mode, "04o")},
            )
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(destination), flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                return Check("native_file_events", Status.DEGRADED, "file-event state changed while opening")
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_STATE_BYTES:
                return Check("native_file_events", Status.DEGRADED, "file-event state exceeded its safety limits")
            if os.name != "nt" and (stat.S_IMODE(opened.st_mode) & 0o077 or opened.st_uid != os.geteuid()):
                return Check("native_file_events", Status.DEGRADED, "file-event state permissions changed")
            payload = handle.read(MAX_STATE_BYTES + 1)
        if len(payload) > MAX_STATE_BYTES:
            return Check("native_file_events", Status.DEGRADED, "file-event state exceeded its size limit")
        document = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        return Check("native_file_events", Status.DEGRADED, "file-event state is invalid", {"error": str(error)})

    if (
        not isinstance(document, dict) or document.get("schema") != 1
        or not set(document).issubset(STATE_FIELDS)
        or document.get("path_data_retained") is not False
    ):
        return Check("native_file_events", Status.DEGRADED, "file-event state schema is invalid")
    pid = document.get("pid")
    updated = _timestamp(document.get("updated_at"))
    last_event_raw = document.get("last_event_at")
    last_event = _timestamp(last_event_raw) if last_event_raw else None
    numeric_fields = ("events_seen", "triggered_scans", "dropped_events_total", "last_event_id")
    if (
        type(pid) is not int or pid <= 0 or updated is None
        or type(document.get("stream_active")) is not bool
        or type(document.get("unreconciled_drop")) is not bool
        or type(document.get("roots_watched")) is not int or not 0 <= document["roots_watched"] <= 16
        or type(document.get("latency_seconds")) not in (int, float)
        or not 0.1 <= document["latency_seconds"] <= 60
        or any(type(document.get(field)) is not int or document[field] < 0 for field in numeric_fields)
        or (last_event_raw is not None and last_event is None)
    ):
        return Check("native_file_events", Status.DEGRADED, "file-event state fields are invalid")

    observed = now or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    age = (observed.astimezone(timezone.utc) - updated).total_seconds()
    alive = _process_alive(pid)
    details = {
        "stream_active": document["stream_active"],
        "host_process_alive": alive,
        "roots_watched": document["roots_watched"],
        "latency_seconds": document["latency_seconds"],
        "heartbeat_age_seconds": round(age, 3),
        "events_seen": document["events_seen"],
        "triggered_scans": document["triggered_scans"],
        "dropped_events_total": document["dropped_events_total"],
        "unreconciled_drop": document["unreconciled_drop"],
        "last_event_id": document["last_event_id"],
        "last_event_at": last_event.isoformat() if last_event else None,
        "path_data_retained": False,
    }
    if not alive:
        return Check("native_file_events", Status.UNHEALTHY, "native file-event host is not running", details)
    if age < -300 or age > MAX_HEARTBEAT_AGE_SECONDS:
        return Check("native_file_events", Status.DEGRADED, "native file-event heartbeat is stale", details)
    if not document["stream_active"] or document["roots_watched"] == 0:
        return Check("native_file_events", Status.UNHEALTHY, "protected-folder event stream is unavailable", details)
    if document["roots_watched"] != 3:
        return Check("native_file_events", Status.DEGRADED, "some protected-folder event roots are unavailable", details)
    if document["unreconciled_drop"]:
        return Check("native_file_events", Status.DEGRADED, "file-event loss requires snapshot reconciliation", details)
    return Check("native_file_events", Status.HEALTHY, "near-real-time protected-folder triggers are active", details)
