"""Quota-limited, content-addressed recovery copies for ransomware response."""

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .ransomware import DEFAULT_MAX_FILES, _capture_filesystem


SCHEMA_VERSION = 1
DEFAULT_QUOTA_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_VERSIONS = 3
PROTECTED_EXTENSIONS = {
    ".csv", ".doc", ".docx", ".heic", ".jpeg", ".jpg", ".md", ".numbers",
    ".pages", ".pdf", ".png", ".ppt", ".pptx", ".rtf", ".text", ".txt",
    ".xls", ".xlsx",
}


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _atomic_json(path: Path, document: Dict[str, object]) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(path.parent), prefix=".manifest-", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(handle.name, 0o600)
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
        os.chmod(str(path), 0o600)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def _prepare_store(store: Path) -> Tuple[Path, Path, Path]:
    destination = store.expanduser().absolute()
    if destination.exists() and destination.is_symlink():
        raise ValueError("recovery store must not be a symbolic link")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not destination.is_dir():
        raise ValueError("recovery store must be a directory")
    os.chmod(str(destination), 0o700)
    objects = destination / "objects"
    objects.mkdir(mode=0o700, exist_ok=True)
    if objects.is_symlink() or not objects.is_dir():
        raise ValueError("recovery object store is invalid")
    os.chmod(str(objects), 0o700)
    return destination, destination / "manifest.json", objects


def _empty_manifest(roots: Iterable[Path], quota_bytes: int) -> Dict[str, object]:
    return {
        "schema": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": None,
        "quota_bytes": quota_bytes,
        "roots": [str(path.expanduser().absolute()) for path in roots],
        "files": {},
    }


def _load_manifest(path: Path, roots: Iterable[Path], quota_bytes: int) -> Dict[str, object]:
    if not path.exists():
        return _empty_manifest(roots, quota_bytes)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("recovery manifest must be a single-link regular file")
        if metadata.st_size > MAX_MANIFEST_BYTES:
            raise ValueError("recovery manifest exceeds size limit")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            manifest = json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA_VERSION
        or not isinstance(manifest.get("files"), dict) or not isinstance(manifest.get("roots"), list)
    ):
        raise ValueError("invalid recovery manifest")
    return manifest


def _store_usage(objects: Path) -> int:
    total = 0
    for entry in objects.iterdir():
        try:
            metadata = os.lstat(str(entry))
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and len(entry.name) == 64:
            total += metadata.st_size
    return total


def _referenced_digests(files: Dict[str, object]) -> set:
    referenced = set()
    for entry in files.values():
        versions = entry.get("versions", []) if isinstance(entry, dict) else []
        if not isinstance(versions, list):
            continue
        for version in versions:
            digest = version.get("sha256") if isinstance(version, dict) else None
            if _valid_digest(digest):
                referenced.add(digest)
    return referenced


def _prune_unreferenced(objects: Path, files: Dict[str, object]) -> None:
    referenced = _referenced_digests(files)
    for entry in objects.iterdir():
        if not _valid_digest(entry.name) or entry.name in referenced:
            continue
        try:
            metadata = os.lstat(str(entry))
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                entry.unlink()
        except OSError:
            continue


def _safe_read(path: Path, max_bytes: int) -> Tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("recovery source must be a single-link regular file")
        if before.st_size > max_bytes:
            raise ValueError("recovery source exceeds per-file limit")
        chunks = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) > max_bytes or (before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns,
        ):
            raise ValueError("recovery source changed while being copied")
        return payload, after
    finally:
        os.close(descriptor)


def _eligible(path: str, metadata: Dict[str, int], max_file_bytes: int) -> bool:
    return (
        Path(path).suffix.lower() in PROTECTED_EXTENSIONS
        and 0 <= int(metadata.get("size", -1)) <= max_file_bytes
    )


def backup(
    store: Path,
    roots: Iterable[Path],
    *,
    quota_bytes: int = DEFAULT_QUOTA_BYTES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    apply: bool = False,
) -> Dict[str, object]:
    root_list = [path.expanduser().absolute() for path in roots]
    _, manifest_path, objects = _prepare_store(store)
    manifest = _load_manifest(manifest_path, root_list, quota_bytes)
    files = manifest["files"]
    snapshot, available, access_errors, limited = _capture_filesystem(root_list, max_files)
    candidates = []
    for path, metadata in snapshot.items():
        if not _eligible(path, metadata, max_file_bytes):
            continue
        existing = files.get(path, {}) if isinstance(files.get(path), dict) else {}
        versions = existing.get("versions", []) if isinstance(existing.get("versions"), list) else []
        latest = versions[-1] if versions and isinstance(versions[-1], dict) else {}
        if (latest.get("size"), latest.get("mtime_ns"), latest.get("inode")) != (
            metadata["size"], metadata["mtime_ns"], metadata["inode"],
        ):
            candidates.append((path, metadata))
    result: Dict[str, object] = {
        "success": True,
        "applied": apply,
        "planned_files": len(candidates),
        "stored_files": 0,
        "stored_bytes": 0,
        "skipped_files": 0,
        "access_errors": access_errors,
        "limited": limited,
        "available_roots": available,
        "quota_bytes": quota_bytes,
        "used_bytes": _store_usage(objects),
    }
    if not apply:
        return result

    _prune_unreferenced(objects, files)
    used = _store_usage(objects)
    observed_at = datetime.now(timezone.utc).isoformat()
    for raw_path, expected in candidates:
        path = Path(raw_path)
        try:
            payload, metadata = _safe_read(path, max_file_bytes)
        except (OSError, ValueError):
            result["skipped_files"] = int(result["skipped_files"]) + 1
            continue
        if (metadata.st_size, metadata.st_mtime_ns, metadata.st_ino) != (
            expected["size"], expected["mtime_ns"], expected["inode"],
        ):
            result["skipped_files"] = int(result["skipped_files"]) + 1
            continue
        digest = hashlib.sha256(payload).hexdigest()
        object_path = objects / digest
        new_object = not object_path.exists()
        if new_object and used + len(payload) > quota_bytes:
            result["skipped_files"] = int(result["skipped_files"]) + 1
            continue
        if new_object:
            descriptor = os.open(
                str(object_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600,
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(str(object_path), 0o600)
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise
            used += len(payload)
            result["stored_bytes"] = int(result["stored_bytes"]) + len(payload)
        else:
            try:
                stored_payload, _ = _safe_read(object_path, max_file_bytes)
                if stored_payload != payload:
                    raise ValueError("existing recovery object failed verification")
            except (OSError, ValueError):
                result["skipped_files"] = int(result["skipped_files"]) + 1
                continue
        existing = files.get(raw_path, {}) if isinstance(files.get(raw_path), dict) else {}
        versions = existing.get("versions", []) if isinstance(existing.get("versions"), list) else []
        versions = [item for item in versions if isinstance(item, dict)]
        version = {
            "sha256": digest,
            "size": len(payload),
            "mtime_ns": metadata.st_mtime_ns,
            "inode": metadata.st_ino,
            "observed_at": observed_at,
        }
        if not versions or versions[-1].get("sha256") != digest:
            versions = (versions + [version])[-MAX_VERSIONS:]
        else:
            versions[-1] = version
        files[raw_path] = {"versions": versions}
        result["stored_files"] = int(result["stored_files"]) + 1
    manifest["roots"] = available
    manifest["quota_bytes"] = quota_bytes
    manifest["max_file_bytes"] = max_file_bytes
    manifest["updated_at"] = observed_at
    manifest["last_backup"] = {
        "stored_files": result["stored_files"],
        "skipped_files": result["skipped_files"],
        "access_errors": access_errors,
        "limited": limited,
    }
    _atomic_json(manifest_path, manifest)
    _prune_unreferenced(objects, files)
    result["used_bytes"] = _store_usage(objects)
    result["recoverable_files"] = len(files)
    return result


def status(store: Path) -> Dict[str, object]:
    if not store.expanduser().absolute().exists():
        return {"enabled": False, "recoverable_files": 0, "used_bytes": 0}
    _, manifest_path, objects = _prepare_store(store)
    if not manifest_path.exists():
        return {"enabled": False, "recoverable_files": 0, "used_bytes": 0}
    manifest = _load_manifest(manifest_path, [], DEFAULT_QUOTA_BYTES)
    version_count = sum(
        len(entry.get("versions", [])) for entry in manifest["files"].values()
        if isinstance(entry, dict) and isinstance(entry.get("versions"), list)
    )
    return {
        "enabled": True,
        "recoverable_files": len(manifest["files"]),
        "versions": version_count,
        "used_bytes": _store_usage(objects),
        "quota_bytes": int(manifest.get("quota_bytes", DEFAULT_QUOTA_BYTES)),
        "updated_at": manifest.get("updated_at"),
        "last_backup": manifest.get("last_backup", {}),
    }


def _version_for_recovery(versions: List[Dict[str, object]]) -> Optional[Dict[str, object]]:
    if not versions:
        return None
    return versions[-2] if len(versions) >= 2 else versions[-1]


def _relative_recovery_path(source: str, roots: List[str]) -> Path:
    source_path = Path(os.path.abspath(source))
    for raw_root in roots:
        root = Path(os.path.abspath(raw_root))
        try:
            relative = source_path.relative_to(root)
        except ValueError:
            continue
        return Path(root.name or "Protected Files") / relative
    return Path("Other") / source_path.name


def restore_all(store: Path, destination: Path, *, apply: bool = False) -> Dict[str, object]:
    _, manifest_path, objects = _prepare_store(store)
    if not manifest_path.exists():
        raise ValueError("recovery vault is not enabled")
    manifest = _load_manifest(manifest_path, [], DEFAULT_QUOTA_BYTES)
    recoverable = []
    for source, entry in sorted(manifest["files"].items()):
        if not isinstance(entry, dict) or not isinstance(entry.get("versions"), list):
            continue
        valid_versions = [item for item in entry["versions"] if isinstance(item, dict)]
        version = _version_for_recovery(valid_versions)
        if version and _valid_digest(version.get("sha256")):
            recoverable.append((source, version))
    total_bytes = sum(int(version.get("size", 0)) for _, version in recoverable)
    result: Dict[str, object] = {
        "success": True,
        "applied": apply,
        "planned_files": len(recoverable),
        "planned_bytes": total_bytes,
        "destination": str(destination.expanduser().absolute()),
        "restored_files": 0,
        "skipped_files": 0,
    }
    if not apply:
        return result
    output = destination.expanduser().absolute()
    if output.exists():
        raise ValueError("recovery destination already exists")
    output.mkdir(mode=0o700, parents=True)
    os.chmod(str(output), 0o700)
    roots = [str(item) for item in manifest.get("roots", []) if isinstance(item, str)]
    for source, version in recoverable:
        digest = str(version["sha256"])
        blob = objects / digest
        try:
            object_limit = int(manifest.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES))
            payload, _ = _safe_read(blob, object_limit)
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError("recovery object digest mismatch")
            target = (output / _relative_recovery_path(source, roots)).absolute()
            if os.path.commonpath((str(output), str(target))) != str(output):
                raise ValueError("recovery target escaped destination")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                raise ValueError("recovery destination collision")
            descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise
            result["restored_files"] = int(result["restored_files"]) + 1
        except (OSError, ValueError):
            result["skipped_files"] = int(result["skipped_files"]) + 1
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rattler recovery", description="Local ransomware recovery vault")
    commands = parser.add_subparsers(dest="command", required=True)
    backup_command = commands.add_parser("backup", help="plan or update recovery copies")
    backup_command.add_argument("--store", required=True)
    backup_command.add_argument("--root", action="append", required=True)
    backup_command.add_argument("--quota-bytes", type=int, default=DEFAULT_QUOTA_BYTES)
    backup_command.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    backup_command.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    backup_command.add_argument("--apply", action="store_true")
    status_command = commands.add_parser("status", help="show recovery-vault status")
    status_command.add_argument("--store", required=True)
    restore_command = commands.add_parser("restore-all", help="recover copies into a new directory")
    restore_command.add_argument("--store", required=True)
    restore_command.add_argument("--destination", required=True)
    restore_command.add_argument("--apply", action="store_true")
    for command in (backup_command, status_command, restore_command):
        command.add_argument("--pretty", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "backup":
            if args.quota_bytes <= 0 or args.max_file_bytes <= 0 or args.max_files <= 0:
                _parser().error("recovery limits must be greater than zero")
            result = backup(
                Path(args.store), [Path(item) for item in args.root], quota_bytes=args.quota_bytes,
                max_file_bytes=args.max_file_bytes, max_files=args.max_files, apply=args.apply,
            )
        elif args.command == "status":
            result = status(Path(args.store))
        else:
            result = restore_all(Path(args.store), Path(args.destination), apply=args.apply)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        result = {"success": False, "error": str(error)}
        print(json.dumps(result, indent=2 if getattr(args, "pretty", False) else None, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
