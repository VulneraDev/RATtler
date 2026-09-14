"""Read-only ransomware behavior detection using bounded filesystem snapshots.

The sensor records file metadata, not file contents. It looks for changes that
commonly accompany ransomware while RATtler is open: bulk rewrites, rapid
extension replacement, ransom-note creation, mass deletion, and damage to a
local canary. It reports evidence but never blocks or modifies user files.
"""

import hashlib
import json
import os
import stat
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .model import Check, Event, Finding, Severity, Status


SCHEMA_VERSION = 1
MAX_STATE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_FILES = 25000
REWRITE_ALERT_THRESHOLD = 40
MASS_DELETE_THRESHOLD = 40
SUSPICIOUS_EXTENSION_THRESHOLD = 2
CANARY_NAME = "ransomware-canary.txt"
CANARY_CONTENT = (
    b"RATtler ransomware detection canary\n"
    b"This harmless local file helps detect destructive file changes.\n"
)
CANARY_SHA256 = hashlib.sha256(CANARY_CONTENT).hexdigest()
SKIP_DIRECTORIES = {".git", ".svn", "node_modules", "__pycache__"}
ENCRYPTED_SUFFIXES = {
    ".crypted", ".crypto", ".crypt", ".encrypted", ".enc", ".locked",
    ".lockbit", ".ryk", ".ryuk", ".wannacry", ".wncry",
}
RANSOM_NOTE_NAMES = {
    "decrypt_instructions.txt", "how_to_decrypt.txt", "how_to_restore_files.txt",
    "readme_to_decrypt.txt", "recover_files.txt", "restore_files.txt",
}


def _private_atomic_write(path: Path, document: Dict[str, object]) -> None:
    destination = path.expanduser().absolute()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(destination.parent),
            prefix=".rattler-ransomware-", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(handle.name, 0o600)
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(destination))
        os.chmod(str(destination), 0o600)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def _load_state(path: Path) -> Optional[Dict[str, object]]:
    destination = path.expanduser().absolute()
    if not destination.exists():
        return None
    metadata = os.lstat(str(destination))
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("ransomware state must be a regular file")
    if metadata.st_size > MAX_STATE_BYTES:
        raise ValueError("ransomware state exceeds size limit")
    with destination.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or document.get("schema") != SCHEMA_VERSION:
        raise ValueError("unsupported ransomware-state schema")
    if not isinstance(document.get("files"), dict) or not isinstance(document.get("roots"), list):
        raise ValueError("invalid ransomware-state document")
    return document


def _ensure_canary(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600,
        )
    except FileExistsError:
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(CANARY_CONTENT)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(str(path), 0o600)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _canary_status(path: Path) -> str:
    try:
        metadata = os.lstat(str(path))
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return "replaced"
        if metadata.st_size > 4096:
            return "modified"
        with path.open("rb") as handle:
            digest = hashlib.sha256(handle.read(4097)).hexdigest()
        return "healthy" if digest == CANARY_SHA256 else "modified"
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unreadable"


def _capture_filesystem(
    roots: Iterable[Path], max_files: int,
) -> Tuple[Dict[str, Dict[str, int]], List[str], int, bool]:
    files: Dict[str, Dict[str, int]] = {}
    available = []
    access_errors = 0
    requested_roots = list(roots)
    work: List[List[Path]] = []
    for requested in requested_roots:
        root = requested.expanduser().absolute()
        try:
            metadata = os.lstat(str(root))
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                access_errors += 1
                continue
        except FileNotFoundError:
            continue
        except OSError:
            access_errors += 1
            continue
        available.append(str(root))
        work.append([root])

    examined = 0
    examination_limit = max_files * 8
    while len(files) < max_files and examined < examination_limit and any(work):
        next_work = []
        round_batch = max(1, min(128, max_files // max(1, len(work) * 8)))
        for stack in work:
            batch = 0
            while stack and batch < round_batch and len(files) < max_files and examined < examination_limit:
                path = stack.pop()
                batch += 1
                examined += 1
                try:
                    item = os.lstat(str(path))
                except OSError:
                    access_errors += 1
                    continue
                if stat.S_ISLNK(item.st_mode):
                    continue
                if stat.S_ISDIR(item.st_mode):
                    if path.name in SKIP_DIRECTORIES:
                        continue
                    try:
                        with os.scandir(str(path)) as iterator:
                            entries = sorted(iterator, key=lambda entry: entry.name, reverse=True)
                        stack.extend(Path(entry.path) for entry in entries)
                    except OSError:
                        access_errors += 1
                elif stat.S_ISREG(item.st_mode):
                    files[str(path)] = {
                        "size": int(item.st_size),
                        "mtime_ns": int(item.st_mtime_ns),
                        "inode": int(item.st_ino),
                    }
            if stack:
                next_work.append(stack)
        work = next_work
    limited = bool(work)
    return files, available, access_errors, limited


def _ransom_notes(paths: Iterable[str]) -> List[str]:
    notes = []
    for path in paths:
        name = os.path.basename(path).lower()
        if name in RANSOM_NOTE_NAMES or (
            name.endswith((".txt", ".html", ".hta"))
            and "decrypt" in name and ("readme" in name or "instruction" in name)
        ):
            notes.append(path)
    return sorted(notes)


def _encrypted_paths(paths: Iterable[str]) -> List[str]:
    return sorted(path for path in paths if Path(path).suffix.lower() in ENCRYPTED_SUFFIXES)


def _event(event_type: str, severity: Severity, evidence: Dict[str, object], observed_at: str) -> Event:
    return Event(str(uuid.uuid4()), event_type, severity, observed_at, evidence)


def scan_ransomware(
    state_path: Path,
    roots: Iterable[Path],
    max_files: int = DEFAULT_MAX_FILES,
) -> Tuple[Check, List[Finding], List[Event]]:
    """Compare a bounded filesystem snapshot with the previous scan."""
    observed_at = datetime.now(timezone.utc).isoformat()
    state_destination = state_path.expanduser().absolute()
    canary_path = state_destination.with_name(CANARY_NAME)
    try:
        previous = _load_state(state_destination)
        if previous is None:
            _ensure_canary(canary_path)
        canary = _canary_status(canary_path)
        requested_roots = list(roots)
        files, available, access_errors, limited = _capture_filesystem(requested_roots, max_files)
        root_names = [Path(path).name or path for path in available]
        previous_files = previous.get("files", {}) if previous else {}
        comparable = previous is not None and previous.get("roots") == available
        created = sorted(set(files) - set(previous_files)) if comparable else []
        deleted = sorted(set(previous_files) - set(files)) if comparable else []
        modified = sorted(
            path for path in set(files).intersection(previous_files)
            if files[path] != previous_files[path]
        ) if comparable else []
        encrypted = _encrypted_paths(created)
        deleted_paths = {path.lower() for path in deleted}
        extension_replacements = []
        for path in encrypted:
            suffix = Path(path).suffix
            original = path[:-len(suffix)] if suffix else path
            if original.lower() in deleted_paths:
                extension_replacements.append(path)
        notes = _ransom_notes(created)
        findings: List[Finding] = []
        events: List[Event] = []

        if canary != "healthy":
            evidence = {"canary": str(canary_path), "state": canary}
            findings.append(Finding(
                "RAT-RANSOM-001", "Ransomware canary changed", Severity.CRITICAL,
                "ransomware", "RATtler's local decoy file was modified, removed, or replaced.", evidence,
            ))
            events.append(_event("ransomware_canary_changed", Severity.CRITICAL, evidence, observed_at))
        if len(extension_replacements) >= SUSPICIOUS_EXTENSION_THRESHOLD or len(encrypted) >= 5:
            evidence = {
                "extension_replacements": len(extension_replacements),
                "encrypted_names": len(encrypted),
                "examples": (extension_replacements or encrypted)[:8],
            }
            findings.append(Finding(
                "RAT-RANSOM-002", "Files rapidly gained encryption-style extensions", Severity.HIGH,
                "ransomware", "Multiple files were replaced or created with extensions commonly used by ransomware.", evidence,
            ))
            events.append(_event("ransomware_extension_burst", Severity.HIGH, evidence, observed_at))
        if len(modified) >= REWRITE_ALERT_THRESHOLD:
            evidence = {"modified_files": len(modified), "examples": modified[:8]}
            findings.append(Finding(
                "RAT-RANSOM-003", "Unusual bulk file rewrite activity", Severity.MEDIUM,
                "ransomware", "Many protected files changed between scans; verify that a trusted bulk operation is running.", evidence,
            ))
            events.append(_event("ransomware_rewrite_burst", Severity.MEDIUM, evidence, observed_at))
        if notes:
            evidence = {"notes": notes[:8], "count": len(notes)}
            findings.append(Finding(
                "RAT-RANSOM-004", "Possible ransom instructions appeared", Severity.HIGH,
                "ransomware", "A new file name resembles instructions commonly left after encryption.", evidence,
            ))
            events.append(_event("ransomware_note_created", Severity.HIGH, evidence, observed_at))
        if len(deleted) >= MASS_DELETE_THRESHOLD and len(deleted) >= max(1, int(len(previous_files) * 0.1)):
            evidence = {"deleted_files": len(deleted), "examples": deleted[:8]}
            findings.append(Finding(
                "RAT-RANSOM-005", "Unusual mass file deletion", Severity.MEDIUM,
                "ransomware", "A large portion of the protected file snapshot disappeared between scans.", evidence,
            ))
            events.append(_event("ransomware_deletion_burst", Severity.MEDIUM, evidence, observed_at))

        document: Dict[str, object] = {
            "schema": SCHEMA_VERSION,
            "observed_at": observed_at,
            "roots": available,
            "files": files,
        }
        _private_atomic_write(state_destination, document)
        if not available:
            sensor_status = Status.UNKNOWN
            message = "protected folders are unavailable"
        elif len(available) < len(requested_roots) or access_errors >= max(20, int(len(files) * 0.01)):
            sensor_status = Status.DEGRADED
            message = "ransomware monitoring coverage is partial"
        else:
            sensor_status = Status.HEALTHY
            message = "no encryption pattern detected" if comparable else "ransomware baseline initialized"
            if limited:
                message = "bounded ransomware coverage active" if comparable else "bounded ransomware baseline initialized"
        details = {
            "initialized": comparable,
            "monitored_files": len(files),
            "protected_folders": root_names,
            "modified_files": len(modified),
            "created_files": len(created),
            "deleted_files": len(deleted),
            "extension_replacements": len(extension_replacements),
            "encrypted_names": len(encrypted),
            "ransom_notes": len(notes),
            "canary": canary,
            "access_errors": access_errors,
            "limited": limited,
            "max_files": max_files,
            "detection_mode": "change snapshots while RATtler is open",
        }
        return Check("ransomware", sensor_status, message, details), findings, events
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        return Check(
            "ransomware", Status.UNKNOWN, "ransomware monitoring state unavailable",
            {"error": str(error), "canary": _canary_status(canary_path)},
        ), [], []
