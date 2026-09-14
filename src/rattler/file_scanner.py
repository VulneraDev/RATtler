"""Bounded, local file inspection with optional YARA rule evaluation."""

import argparse
import hashlib
import json
import math
import os
import platform
import stat
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .behavior import suspicious_location
from .injection import MACHO_MAGICS, signature_info
from .model import Check, Finding, Severity, Status


DEFAULT_MAX_FILES = 2000
DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_SECONDS = 120
MAX_DIRECTORIES = 10000
MAX_FINDINGS = 500
MAX_FILE_RECORDS = 250
READ_CHUNK = 1024 * 1024
ENTROPY_SAMPLE_BYTES = 4 * 1024 * 1024
YARA_TIMEOUT_SECONDS = 10
MAX_RULE_BYTES = 64 * 1024 * 1024
SEVERITIES = {item.value: item for item in Severity}
EXECUTABLE_SUFFIXES = {
    ".app", ".command", ".dylib", ".exe", ".jar", ".pkg", ".scr", ".sh", ".so",
}
DOCUMENT_SUFFIXES = {
    ".csv", ".doc", ".docx", ".gif", ".heic", ".jpeg", ".jpg", ".numbers",
    ".pages", ".pdf", ".png", ".ppt", ".pptx", ".rtf", ".txt", ".xls", ".xlsx",
}


def _safe_target(path: Path) -> Path:
    requested = path.expanduser()
    if requested.is_symlink():
        raise ValueError("scan targets must not be symbolic links")
    target = requested.resolve()
    if not target.exists():
        raise ValueError("scan target does not exist")
    if not target.is_file() and not target.is_dir():
        raise ValueError("scan target must be a regular file or directory")
    return target


def discover_files(target: Path, recursive: bool, max_files: int) -> Tuple[List[Path], Dict[str, object]]:
    if max_files <= 0 or max_files > 10000:
        raise ValueError("maximum files must be between 1 and 10000")
    resolved = _safe_target(target)
    if resolved.is_file():
        return [resolved], {"file_limit_reached": False, "directory_limit_reached": False, "directories": 0}
    files = []
    directories = 0
    file_limit = False
    directory_limit = False
    for root, names, filenames in os.walk(resolved, topdown=True, followlinks=False):
        directories += 1
        names[:] = sorted(name for name in names if not (Path(root) / name).is_symlink())
        if not recursive:
            names[:] = []
        for name in sorted(filenames):
            candidate = Path(root) / name
            try:
                metadata = candidate.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                continue
            files.append(candidate)
            if len(files) > max_files:
                files = files[:max_files]
                file_limit = True
                names[:] = []
                break
        if directories >= MAX_DIRECTORIES:
            directory_limit = True
            break
        if file_limit:
            break
    return files, {
        "file_limit_reached": file_limit,
        "directory_limit_reached": directory_limit,
        "directories": directories,
    }


def _entropy(counts: Counter, length: int) -> float:
    if length <= 0:
        return 0.0
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def inspect_file(
    path: Path,
    max_file_bytes: int,
) -> Tuple[Optional[Dict[str, object]], Optional[bytes], Optional[str]]:
    descriptor = None
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            return None, None, "not a regular file"
        if metadata.st_size > max_file_bytes:
            return None, None, "file exceeds the per-file size limit"
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev, opened.st_ino, opened.st_size
        ) != (metadata.st_dev, metadata.st_ino, metadata.st_size):
            return None, None, "file changed before inspection"
        digest = hashlib.sha256()
        counts = Counter()
        content = bytearray()
        sampled = 0
        magic = b""
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            while True:
                chunk = handle.read(READ_CHUNK)
                if not chunk:
                    break
                if not magic:
                    magic = chunk[:4]
                digest.update(chunk)
                content.extend(chunk)
                if sampled < ENTROPY_SAMPLE_BYTES:
                    sample = chunk[:ENTROPY_SAMPLE_BYTES - sampled]
                    counts.update(sample)
                    sampled += len(sample)
        final_metadata = path.lstat()
        if not stat.S_ISREG(final_metadata.st_mode) or stat.S_ISLNK(final_metadata.st_mode) or (
            final_metadata.st_dev, final_metadata.st_ino, final_metadata.st_size,
            final_metadata.st_mtime_ns,
        ) != (
            metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
        ):
            return None, None, "file changed during inspection"
    except OSError as error:
        return None, None, str(error)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    macho = magic in MACHO_MAGICS
    signature = signature_info(str(path)) if macho and platform.system() == "Darwin" else None
    try:
        post_signature = path.lstat()
        if not stat.S_ISREG(post_signature.st_mode) or stat.S_ISLNK(post_signature.st_mode) or (
            post_signature.st_dev, post_signature.st_ino, post_signature.st_size,
            post_signature.st_mtime_ns,
        ) != (
            metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
        ):
            return None, None, "file changed during signature inspection"
    except OSError as error:
        return None, None, str(error)
    quarantined = False
    if platform.system() == "Darwin" and hasattr(os, "getxattr"):
        try:
            quarantined = bool(os.getxattr(str(path), "com.apple.quarantine"))
        except OSError:
            pass
    return {
        "path": str(path),
        "sha256": digest.hexdigest(),
        "size": metadata.st_size,
        "mode": metadata.st_mode & 0o7777,
        "executable": bool(metadata.st_mode & 0o111),
        "macho": macho,
        "entropy": round(_entropy(counts, sampled), 3),
        "entropy_sample_bytes": sampled,
        "quarantine_attribute": quarantined,
        "signature": signature.kind if signature else None,
        "signature_valid": signature.valid if signature else None,
        "team_id": signature.team_id if signature else None,
        "identifier": signature.identifier if signature else None,
        "cdhash": signature.cdhash if signature else None,
    }, bytes(content), None


def _disguised_executable(record: Dict[str, object]) -> bool:
    suffixes = [suffix.lower() for suffix in Path(record["path"]).suffixes]
    return len(suffixes) >= 2 and any(suffix in DOCUMENT_SUFFIXES for suffix in suffixes[:-1]) and suffixes[-1] in EXECUTABLE_SUFFIXES


def static_findings(record: Dict[str, object]) -> List[Finding]:
    findings = []
    path = str(record["path"])
    reason = suspicious_location(path)
    if _disguised_executable(record):
        findings.append(Finding(
            "RAT-FILE-001", "Executable uses a disguised document name", Severity.HIGH,
            "file_scan", "A document-style filename is followed by an executable extension.",
            {"path": path, "sha256": record["sha256"], "suffixes": Path(path).suffixes},
        ))
    if record["macho"] and (
        record["signature"] in ("unsigned", "adhoc") or record["signature_valid"] is False
    ) and reason:
        findings.append(Finding(
            "RAT-FILE-002", "Untrusted Mach-O is staged in a risky location", Severity.HIGH,
            "file_scan", "A native executable in a user-writable staging location has no valid trusted signature.",
            {
                "path": path, "sha256": record["sha256"], "cdhash": record["cdhash"],
                "signature": record["signature"], "signature_valid": record["signature_valid"],
                "location_reason": reason,
            },
        ))
    if (
        record["size"] >= 4096 and record["entropy"] >= 7.5
        and (record["executable"] or record["macho"] or Path(path).suffix.lower() in EXECUTABLE_SUFFIXES)
    ):
        findings.append(Finding(
            "RAT-FILE-003", "Executable content has unusually high entropy", Severity.LOW,
            "file_scan", "Packed, compressed, or encrypted executable content deserves context; entropy alone is not malware evidence.",
            {"path": path, "sha256": record["sha256"], "entropy": record["entropy"]},
        ))
    return findings


def compile_yara(rule_roots: Sequence[Path]):
    if not rule_roots:
        return None, "no YARA rules were configured", []
    try:
        import yara  # type: ignore
    except ImportError:
        return None, "yara-python is not installed", []
    files = []
    for root in rule_roots:
        requested = root.expanduser()
        if requested.is_symlink():
            return None, "YARA rule paths must not be symbolic links", []
        resolved = requested.resolve()
        if resolved.is_file() and resolved.suffix.lower() in (".yar", ".yara"):
            files.append(resolved)
        elif resolved.is_dir():
            files.extend(sorted(
                item for item in resolved.rglob("*")
                if item.is_file() and not item.is_symlink() and item.suffix.lower() in (".yar", ".yara")
            ))
    files = list(dict.fromkeys(files))
    if not files:
        return None, "no YARA rule files were found", []
    if len(files) > 1000:
        return None, "YARA rule file limit exceeded", []
    manifest = []
    namespaces = {}
    total_rule_bytes = 0
    try:
        for index, path in enumerate(files):
            if path.stat().st_size > 10 * 1024 * 1024:
                return None, "an individual YARA rule file exceeds 10 MiB", []
            namespace = "rattler_%04d" % index
            content = path.read_bytes()
            total_rule_bytes += len(content)
            if total_rule_bytes > MAX_RULE_BYTES:
                return None, "combined YARA rule sources exceed 64 MiB", []
            namespaces[namespace] = str(path)
            manifest.append({
                "namespace": namespace, "source": path.name,
                "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
                "_path": str(path),
            })
    except OSError as error:
        return None, "YARA rules could not be read: %s" % error, []
    try:
        return yara.compile(filepaths=namespaces), None, manifest
    except Exception as error:
        return None, "YARA rules could not be compiled: %s" % error, manifest


def yara_findings(
    compiled,
    record: Dict[str, object],
    content: bytes,
    manifest: Sequence[Dict[str, object]] = (),
) -> Tuple[List[Finding], Optional[str]]:
    if compiled is None:
        return [], None
    try:
        matches = compiled.match(data=content, timeout=YARA_TIMEOUT_SECONDS)
    except Exception as error:
        return [], str(error)
    findings = []
    for match in matches:
        metadata = dict(getattr(match, "meta", {}) or {})
        raw_severity = str(metadata.get("severity", "medium")).lower()
        severity = SEVERITIES.get(raw_severity, Severity.MEDIUM)
        rule = str(getattr(match, "rule", "unknown"))
        namespace = str(getattr(match, "namespace", "default"))
        source = next((item for item in manifest if item.get("namespace") == namespace), {})
        tags = [str(item) for item in (getattr(match, "tags", []) or [])]
        rule_identity = "%s:%s" % (source.get("sha256", "unknown"), rule)
        rule_id = "RAT-FILE-YARA-" + hashlib.sha256(rule_identity.encode("utf-8")).hexdigest()[:24]
        findings.append(Finding(
            rule_id, "YARA rule matched: %s" % rule, severity,
            "file_scan", str(metadata.get("description", "A local YARA rule matched this file.")),
            {
                "path": record["path"], "sha256": record["sha256"], "rule": rule,
                "namespace": namespace, "tags": tags,
                "rule_source": source.get("source"),
                "rule_source_sha256": source.get("sha256"),
                "confidence": metadata.get("confidence", "unspecified"),
            },
        ))
    return findings, None


def scan_target(
    target: Path,
    rule_roots: Sequence[Path] = (),
    recursive: bool = True,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_seconds: int = DEFAULT_MAX_SECONDS,
    exception_policy: Optional[Path] = None,
) -> Dict[str, object]:
    if max_file_bytes <= 0 or max_file_bytes > 1024 * 1024 * 1024:
        raise ValueError("per-file byte limit must be between 1 and 1 GiB")
    if max_total_bytes <= 0 or max_total_bytes > 8 * 1024 * 1024 * 1024:
        raise ValueError("total byte limit must be between 1 and 8 GiB")
    if max_seconds <= 0 or max_seconds > 3600:
        raise ValueError("scan time limit must be between 1 and 3600 seconds")
    resolved = _safe_target(target)
    files, discovery = discover_files(resolved, recursive, max_files)
    compiled, yara_error, rule_manifest = compile_yara(rule_roots)
    rule_source_paths = {item.get("_path") for item in rule_manifest}
    records = []
    findings = []
    errors = []
    skipped = 0
    scanned = 0
    total_bytes = 0
    total_limit = False
    time_limit = False
    deadline = time.monotonic() + max_seconds
    for path in files:
        if time.monotonic() >= deadline:
            time_limit = True
            break
        # Do not let a configured rule source alert on its own detection strings.
        if str(path.resolve()) in rule_source_paths:
            skipped += 1
            continue
        try:
            size = path.stat().st_size
        except OSError as error:
            errors.append({"path": str(path), "error": str(error)})
            continue
        if size > max_file_bytes:
            skipped += 1
            if len(errors) < 100:
                errors.append({"path": str(path), "error": "file exceeds the per-file size limit"})
            continue
        if total_bytes + size > max_total_bytes:
            total_limit = True
            break
        record, content, error = inspect_file(path, max_file_bytes)
        if record is None:
            skipped += 1
            if error and len(errors) < 100:
                errors.append({"path": str(path), "error": error})
            continue
        total_bytes += int(record["size"])
        scanned += 1
        file_findings = static_findings(record)
        if time.monotonic() >= deadline:
            findings.extend(file_findings[:max(0, MAX_FINDINGS - len(findings))])
            if len(records) < MAX_FILE_RECORDS:
                records.append({**record, "finding_count": len(file_findings)})
            time_limit = True
            break
        yara_matches, match_error = yara_findings(compiled, record, content or b"", rule_manifest)
        if match_error and len(errors) < 100:
            errors.append({"path": str(path), "error": "YARA: %s" % match_error})
        file_findings.extend(yara_matches)
        findings.extend(file_findings[:max(0, MAX_FINDINGS - len(findings))])
        if len(records) < MAX_FILE_RECORDS:
            records.append({**record, "finding_count": len(file_findings)})
    limited = bool(
        discovery["file_limit_reached"] or discovery["directory_limit_reached"]
        or total_limit or time_limit
    )
    if yara_error:
        check_status = Status.UNKNOWN if rule_roots else Status.DEGRADED
        check_message = "static inspection completed; YARA coverage unavailable"
    elif errors:
        check_status = Status.DEGRADED
        check_message = "file inspection completed with unreadable or timed-out files"
    elif limited:
        check_status = Status.DEGRADED
        check_message = "file inspection reached a configured safety limit"
    else:
        check_status = Status.HEALTHY
        check_message = "bounded file inspection completed"
    check = Check(
        "file_scanner", check_status, check_message,
        {
            "target": str(resolved), "scanned_files": scanned,
            "reported_files": len(records), "skipped_files": skipped, "bytes_read": total_bytes,
            "yara_rules": len(rule_manifest), "yara_error": yara_error, "limited": limited,
            **discovery, "total_byte_limit_reached": total_limit,
            "time_limit_reached": time_limit, "max_seconds": max_seconds,
        },
    )
    exception_check = None
    if exception_policy is not None:
        from .suppressions import apply_exceptions

        exception_check, findings, _events = apply_exceptions(exception_policy, findings, [])
    highest = max((item.severity for item in findings), key=lambda item: list(Severity).index(item), default=None)
    status = "risk" if highest in (Severity.CRITICAL, Severity.HIGH) else "review" if findings else "clean"
    return {
        "status": status,
        "target": str(resolved),
        "check": asdict(check),
        "exception_check": asdict(exception_check) if exception_check else None,
        "summary": {
            "scanned_files": check.details["scanned_files"], "reported_files": len(records),
            "findings": len(findings), "bytes_read": total_bytes, "errors": len(errors),
            "limited": limited, "yara_rules": len(rule_manifest),
            "suppressed_findings": exception_check.details.get("suppressed_findings", 0) if exception_check else 0,
        },
        "findings": [asdict(item) for item in findings],
        "files": records,
        "errors": errors,
        "rule_manifest": [
            {key: value for key, value in item.items() if key != "_path"}
            for item in rule_manifest
        ],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rattler files", description="Run bounded local file inspection.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("target", type=Path)
    scan.add_argument("--rules", type=Path, action="append", default=[])
    scan.add_argument("--exceptions", type=Path)
    scan.add_argument("--no-recursive", action="store_true")
    scan.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    scan.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    scan.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    scan.add_argument("--max-seconds", type=int, default=DEFAULT_MAX_SECONDS)
    scan.add_argument("--pretty", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = scan_target(
            args.target, args.rules, not args.no_recursive, args.max_files,
            args.max_file_bytes, args.max_total_bytes,
            args.max_seconds,
            args.exceptions,
        )
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"error": "file scan refused", "detail": str(error)}), file=os.sys.stderr)
        return 2
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 3 if result["status"] == "risk" else 1 if result["status"] == "review" else 0


if __name__ == "__main__":
    raise SystemExit(main())
