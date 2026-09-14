"""Assurance sensor for RATtler's native continuous-operation controller."""

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .model import Check, Status


MAX_STATE_BYTES = 64 * 1024
MIN_INTERVAL_SECONDS = 30
MAX_INTERVAL_SECONDS = 3600


def _timestamp(value: object) -> Optional[datetime]:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _process_alive(pid: int) -> bool:
    if os.name == "nt":
        # Unlike POSIX, os.kill(pid, 0) may terminate a process on Windows.
        # Query the handle and exit code without mutating the target instead.
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return ctypes.get_last_error() == 5  # access denied still implies a live PID
        try:
            exit_code = wintypes.DWORD()
            return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))) and exit_code.value == 259
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def continuous_operation_sensor(path: Path, now: Optional[datetime] = None) -> Check:
    destination = path.expanduser().absolute()
    try:
        metadata = os.lstat(str(destination))
    except OSError as error:
        return Check("continuous_operation", Status.UNKNOWN, "operation heartbeat unavailable", {"error": str(error)})
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return Check("continuous_operation", Status.DEGRADED, "operation heartbeat is not a safe regular file")
    if metadata.st_size > MAX_STATE_BYTES:
        return Check("continuous_operation", Status.DEGRADED, "operation heartbeat exceeded its size limit")
    if os.name != "nt":
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & 0o077 or metadata.st_uid != os.geteuid():
            return Check(
                "continuous_operation", Status.DEGRADED,
                "operation heartbeat permissions need review", {"mode": format(mode, "04o")},
            )
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(destination), flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                return Check("continuous_operation", Status.DEGRADED, "operation heartbeat changed while opening")
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_STATE_BYTES:
                return Check("continuous_operation", Status.DEGRADED, "operation heartbeat exceeded its safety limits")
            if os.name != "nt" and (stat.S_IMODE(opened.st_mode) & 0o077 or opened.st_uid != os.geteuid()):
                return Check("continuous_operation", Status.DEGRADED, "operation heartbeat permissions changed")
            payload = handle.read(MAX_STATE_BYTES + 1)
        if len(payload) > MAX_STATE_BYTES:
            return Check("continuous_operation", Status.DEGRADED, "operation heartbeat exceeded its size limit")
        document = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        return Check("continuous_operation", Status.DEGRADED, "operation heartbeat is invalid", {"error": str(error)})
    if not isinstance(document, dict) or document.get("schema") != 1:
        return Check("continuous_operation", Status.DEGRADED, "operation heartbeat schema is invalid")
    operation_status = document.get("status")
    pid = document.get("pid")
    interval = document.get("interval_seconds")
    updated = _timestamp(document.get("updated_at"))
    raw_last_scan = document.get("last_scan_at")
    last_scan = _timestamp(raw_last_scan) if raw_last_scan else None
    if (
        operation_status not in ("active", "paused") or type(pid) is not int or pid <= 0
        or type(interval) is not int or not MIN_INTERVAL_SECONDS <= interval <= MAX_INTERVAL_SECONDS
        or updated is None or (raw_last_scan is not None and last_scan is None)
        or type(document.get("menu_bar")) is not bool
        or type(document.get("launch_at_login")) is not bool
    ):
        return Check("continuous_operation", Status.DEGRADED, "operation heartbeat fields are invalid")
    observed = now or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    age = (observed.astimezone(timezone.utc) - updated).total_seconds()
    details = {
        "operation_status": operation_status,
        "interval_seconds": interval,
        "heartbeat_age_seconds": round(age, 3),
        "host_process_alive": _process_alive(pid),
        "menu_bar": document.get("menu_bar") is True,
        "launch_at_login": document.get("launch_at_login") is True,
        "last_scan_at": last_scan.isoformat() if last_scan else None,
    }
    if not details["host_process_alive"]:
        return Check("continuous_operation", Status.UNHEALTHY, "native monitoring host is not running", details)
    if age < -300 or age > max(interval * 3, 180):
        return Check("continuous_operation", Status.DEGRADED, "operation heartbeat is stale", details)
    if operation_status == "paused":
        return Check("continuous_operation", Status.DEGRADED, "continuous monitoring is explicitly paused", details)
    if not details["menu_bar"]:
        return Check("continuous_operation", Status.DEGRADED, "native monitoring controls are unavailable", details)
    return Check("continuous_operation", Status.HEALTHY, "native scan scheduler is active", details)
