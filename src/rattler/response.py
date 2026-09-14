"""Explicit, reversible endpoint response operations.

Quarantine is intentionally operator-driven. A dry run computes the exact file
hash; applying the action requires that hash so a changed path is never moved by
mistake. The implementation refuses links, non-regular files, protected OS
paths, and cross-filesystem moves.
"""

import hashlib
import json
import os
import re
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_REASON_LENGTH = 500
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ENTRY_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
PROTECTED_PREFIXES = (
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/lib",
    "/lib64",
    "/boot",
    "/Library/Apple",
)


class ResponseError(ValueError):
    """Raised when a response action fails a safety invariant."""


def default_store() -> Path:
    return Path.home() / ".rattler" / "quarantine"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _atomic_json(path: Path, document: Dict[str, object]) -> None:
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    descriptor = os.open(
        str(temporary),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(str(temporary), str(path))
        os.chmod(str(path), 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def _append_audit(root: Path, event: Dict[str, object]) -> None:
    path = root / "audit.jsonl"
    descriptor = os.open(
        str(path),
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ResponseError("response audit must be a regular file without hard links")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        payload = (json.dumps(event, sort_keys=True) + "\n").encode("utf-8")
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_store(store: Path) -> Path:
    requested = store.expanduser().absolute()
    requested.mkdir(mode=0o700, parents=True, exist_ok=True)
    if requested.is_symlink() or not requested.is_dir():
        raise ResponseError("quarantine store must be a real directory")
    canonical = requested.resolve(strict=True)
    root_metadata = canonical.stat()
    if hasattr(os, "geteuid") and root_metadata.st_uid != os.geteuid():
        raise ResponseError("quarantine store must be owned by the current user")
    os.chmod(str(canonical), 0o700)
    entries = canonical / "entries"
    entries.mkdir(mode=0o700, exist_ok=True)
    if entries.is_symlink() or not entries.is_dir():
        raise ResponseError("quarantine entries path is unsafe")
    entries_metadata = entries.stat()
    if hasattr(os, "geteuid") and entries_metadata.st_uid != os.geteuid():
        raise ResponseError("quarantine entries path must be owned by the current user")
    os.chmod(str(entries), 0o700)
    return canonical


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_protected(path: Path) -> bool:
    rendered = path.as_posix()
    if rendered == "/" or any(
        rendered == prefix or rendered.startswith(prefix + "/")
        for prefix in PROTECTED_PREFIXES
    ):
        return True
    if os.name == "nt":
        candidate = os.path.normcase(str(path.resolve()))
        for variable in ("SystemRoot", "windir"):
            value = os.environ.get(variable)
            if not value:
                continue
            root = os.path.normcase(str(Path(value).resolve()))
            try:
                if os.path.commonpath((candidate, root)) == root:
                    return True
            except ValueError:
                continue
    return False


def _validated_target(target: Path, store: Optional[Path] = None) -> Path:
    requested = target.expanduser().absolute()
    try:
        initial = requested.lstat()
    except FileNotFoundError as error:
        raise ResponseError("target does not exist") from error
    if stat.S_ISLNK(initial.st_mode):
        raise ResponseError("symbolic links cannot be quarantined")
    if not stat.S_ISREG(initial.st_mode):
        raise ResponseError("target must be a regular file")
    resolved = requested.resolve(strict=True)
    if _is_protected(resolved):
        raise ResponseError("protected operating-system paths cannot be quarantined")
    store_root = store.resolve() if store is not None and store.exists() else store
    if store_root is not None and _is_under(resolved, store_root):
        raise ResponseError("files inside the quarantine store cannot be quarantined")
    return resolved


def _inspect_regular(path: Path) -> Tuple[os.stat_result, str]:
    descriptor = os.open(
        str(path),
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ResponseError("target must be a regular file")
        if before.st_nlink != 1:
            raise ResponseError("hard-linked files cannot be quarantined")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ResponseError("target changed while it was being inspected")
        return after, digest.hexdigest()
    finally:
        os.close(descriptor)


def _same_file(metadata: os.stat_result, current: os.stat_result) -> bool:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    ) == (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    )


def _validate_reason(reason: str) -> str:
    cleaned = reason.strip()
    if not cleaned:
        raise ResponseError("an operator reason is required")
    if len(cleaned) > MAX_REASON_LENGTH:
        raise ResponseError("operator reason is too long")
    return cleaned


def quarantine_file(
    target: Path,
    reason: str,
    store: Optional[Path] = None,
    expected_sha256: Optional[str] = None,
    apply: bool = False,
) -> Dict[str, object]:
    """Plan or apply a quarantine action for one exact regular file."""
    reason = _validate_reason(reason)
    requested_store = (store or default_store()).expanduser().absolute()
    resolved = _validated_target(target, requested_store)
    metadata, digest = _inspect_regular(resolved)
    if expected_sha256 is not None and not SHA256_PATTERN.fullmatch(expected_sha256):
        raise ResponseError("expected SHA-256 must be 64 lowercase hexadecimal characters")
    if expected_sha256 is not None and expected_sha256 != digest:
        raise ResponseError("target hash no longer matches the approved SHA-256")
    plan: Dict[str, object] = {
        "action": "quarantine",
        "applied": False,
        "target": str(resolved),
        "sha256": digest,
        "size": metadata.st_size,
        "reason": reason,
        "store": str(requested_store),
    }
    if not apply:
        plan["next_step"] = "repeat with --expected-sha256 and --apply"
        return plan
    if expected_sha256 is None:
        raise ResponseError("--apply requires the SHA-256 returned by a dry run")

    root = _ensure_store(requested_store)
    identifier = uuid.uuid4().hex
    entry = root / "entries" / identifier
    entry.mkdir(mode=0o700)
    payload = entry / "payload"
    original_mode = stat.S_IMODE(metadata.st_mode)
    try:
        current = resolved.lstat()
        if not _same_file(metadata, current):
            raise ResponseError("target changed after operator approval")
        if current.st_dev != entry.stat().st_dev:
            raise ResponseError("quarantine store must be on the same filesystem as the target")
        os.replace(str(resolved), str(payload))
        os.chmod(str(payload), 0o600)
        moved_metadata, moved_digest = _inspect_regular(payload)
        if moved_digest != digest or moved_metadata.st_size != metadata.st_size:
            os.replace(str(payload), str(resolved))
            os.chmod(str(resolved), original_mode & 0o777)
            raise ResponseError("quarantined payload did not match the approved file")
        manifest: Dict[str, object] = {
            "schema": SCHEMA_VERSION,
            "id": identifier,
            "status": "quarantined",
            "original_path": str(resolved),
            "payload": "payload",
            "sha256": digest,
            "size": metadata.st_size,
            "original_mode": original_mode,
            "original_uid": getattr(metadata, "st_uid", None),
            "original_gid": getattr(metadata, "st_gid", None),
            "reason": reason,
            "created_at": _now(),
        }
        _atomic_json(entry / "manifest.json", manifest)
        _append_audit(root, {
            "schema": SCHEMA_VERSION,
            "timestamp": manifest["created_at"],
            "action": "quarantine",
            "id": identifier,
            "original_path": str(resolved),
            "sha256": digest,
            "reason": reason,
        })
    except Exception:
        if payload.exists() and not resolved.exists():
            os.replace(str(payload), str(resolved))
            os.chmod(str(resolved), original_mode & 0o777)
        for child in (entry / "manifest.json",):
            if child.exists():
                child.unlink()
        if entry.exists():
            entry.rmdir()
        raise
    return {
        **plan,
        "applied": True,
        "id": identifier,
        "payload": str(payload),
        "status": "quarantined",
    }


def _load_manifest(root: Path, identifier: str) -> Tuple[Path, Dict[str, object]]:
    if not ENTRY_ID_PATTERN.fullmatch(identifier):
        raise ResponseError("invalid quarantine entry ID")
    entry = root / "entries" / identifier
    manifest_path = entry / "manifest.json"
    if (
        entry.is_symlink()
        or not entry.is_dir()
        or entry.resolve().parent != (root / "entries").resolve()
    ):
        raise ResponseError("quarantine entry path is unsafe")
    descriptor = os.open(
        str(manifest_path),
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        manifest_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(manifest_metadata.st_mode) or manifest_metadata.st_nlink != 1:
            raise ResponseError("quarantine manifest path is unsafe")
        if manifest_metadata.st_size > MAX_MANIFEST_BYTES:
            raise ResponseError("quarantine manifest is too large")
        chunks = []
        remaining = MAX_MANIFEST_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0:
            raise ResponseError("quarantine manifest is too large")
        try:
            manifest = json.loads(b"".join(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ResponseError("invalid quarantine manifest") from error
    finally:
        os.close(descriptor)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != SCHEMA_VERSION
        or manifest.get("id") != identifier
    ):
        raise ResponseError("invalid quarantine manifest")
    return entry, manifest


def list_quarantine(store: Optional[Path] = None) -> List[Dict[str, object]]:
    requested = (store or default_store()).expanduser().absolute()
    if not requested.exists():
        return []
    root = _ensure_store(requested)
    manifests = []
    for entry in sorted((root / "entries").iterdir()):
        if entry.is_symlink() or not entry.is_dir() or not ENTRY_ID_PATTERN.fullmatch(entry.name):
            continue
        try:
            _entry, manifest = _load_manifest(root, entry.name)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        manifests.append(manifest)
    return manifests


def restore_file(
    identifier: str,
    store: Optional[Path] = None,
    apply: bool = False,
) -> Dict[str, object]:
    """Plan or restore one quarantined file to its original path."""
    root = _ensure_store(store or default_store())
    entry, manifest = _load_manifest(root, identifier)
    if manifest.get("status") != "quarantined":
        raise ResponseError("quarantine entry is not available for restore")
    original_value = manifest.get("original_path")
    digest = manifest.get("sha256")
    if not isinstance(original_value, str) or not Path(original_value).is_absolute():
        raise ResponseError("manifest original path is invalid")
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        raise ResponseError("manifest SHA-256 is invalid")
    original = Path(original_value)
    if _is_protected(original) or _is_under(original, root):
        raise ResponseError("manifest restore path is protected")
    payload = entry / "payload"
    metadata, current_digest = _inspect_regular(payload)
    if current_digest != digest:
        raise ResponseError("quarantined payload failed integrity verification")
    if original.exists() or original.is_symlink():
        raise ResponseError("restore destination already exists")
    parent = original.parent
    if not parent.is_dir() or parent.is_symlink() or parent.resolve() != parent.absolute():
        raise ResponseError("restore destination directory is unsafe or missing")
    if parent.stat().st_dev != metadata.st_dev:
        raise ResponseError("restore destination must be on the quarantine filesystem")
    plan: Dict[str, object] = {
        "action": "restore",
        "applied": False,
        "id": identifier,
        "target": str(original),
        "sha256": digest,
        "size": metadata.st_size,
        "status": "quarantined",
    }
    if not apply:
        plan["next_step"] = "repeat with --apply after reviewing the destination"
        return plan

    previous_manifest = dict(manifest)
    os.replace(str(payload), str(original))
    original_mode = manifest.get("original_mode", 0o600)
    if not isinstance(original_mode, int):
        original_mode = 0o600
    os.chmod(str(original), original_mode & 0o777)
    _metadata, restored_digest = _inspect_regular(original)
    if restored_digest != digest:
        os.replace(str(original), str(payload))
        os.chmod(str(payload), 0o600)
        raise ResponseError("restored file failed integrity verification")
    try:
        manifest["status"] = "restored"
        manifest["restored_at"] = _now()
        _atomic_json(entry / "manifest.json", manifest)
        _append_audit(root, {
            "schema": SCHEMA_VERSION,
            "timestamp": manifest["restored_at"],
            "action": "restore",
            "id": identifier,
            "original_path": str(original),
            "sha256": digest,
        })
    except Exception:
        if original.exists() and not payload.exists():
            os.replace(str(original), str(payload))
            os.chmod(str(payload), 0o600)
        _atomic_json(entry / "manifest.json", previous_manifest)
        raise
    return {**plan, "applied": True, "status": "restored"}
