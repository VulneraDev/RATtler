"""Persistent integrity baselines for RAT footholds and loaded code."""

import hashlib
import json
import os
import platform
import plistlib
import socket
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .behavior import suspicious_location
from .injection import (
    _plausible_code_path,
    _user_writable_location,
    is_macho,
    parse_loaded_images,
    signature_metadata,
)
from .model import Check, Finding, Severity, Status
from .runner import run


SCHEMA_VERSION = 1
MAX_BASELINE_BYTES = 32 * 1024 * 1024
MAX_ASSET_BYTES = 1024 * 1024 * 1024


@dataclass(frozen=True)
class Asset:
    path: str
    kind: str


@dataclass(frozen=True)
class Fingerprint:
    path: str
    kind: str
    sha256: str
    size: int
    mode: int
    uid: int
    gid: int
    link_target: Optional[str] = None
    cdhash: Optional[str] = None


def _launchd_roots(home: Optional[str] = None, roots: Optional[Sequence[Path]] = None) -> List[Path]:
    if roots is not None:
        return list(roots)
    return [
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
        Path(home or str(Path.home())) / "Library/LaunchAgents",
    ]


def _launchd_assets(home: Optional[str] = None, roots: Optional[Sequence[Path]] = None) -> List[Asset]:
    assets = []
    for root in _launchd_roots(home, roots):
        try:
            plists = sorted(root.glob("*.plist"))
        except OSError:
            continue
        for path in plists:
            assets.append(Asset(str(path), "launchd_plist"))
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
                with path.open("rb") as handle:
                    data = plistlib.load(handle)
            except (OSError, plistlib.InvalidFileException, ValueError, TypeError):
                continue
            if not isinstance(data, dict):
                continue
            program = data.get("Program")
            if not isinstance(program, str):
                arguments = data.get("ProgramArguments")
                program = arguments[0] if isinstance(arguments, list) and arguments and isinstance(arguments[0], str) else None
            if program and os.path.isabs(program) and os.path.isfile(program):
                assets.append(Asset(program, "startup_executable"))
    return assets


def _loaded_code_assets(home: Optional[str] = None) -> List[Asset]:
    if platform.system() != "Darwin":
        return []
    result = run(["/usr/sbin/lsof", "-nP", "-Fpcftn", "-d", "txt"], timeout=15.0)
    if result is None or result.returncode not in (0, 1):
        return []
    assets = []
    for image in parse_loaded_images(result.stdout):
        path = image.path[:-10] if image.path.endswith(" (deleted)") else image.path
        if not _user_writable_location(path, home):
            continue
        if not _plausible_code_path(path, suspicious_location(path, home)) or not is_macho(path):
            continue
        assets.append(Asset(path, "loaded_macho"))
    return assets


def discover_assets(
    home: Optional[str] = None,
    launchd_roots: Optional[Sequence[Path]] = None,
    include_loaded_code: bool = True,
) -> List[Asset]:
    assets = _launchd_assets(home, launchd_roots)
    if include_loaded_code:
        assets.extend(_loaded_code_assets(home))
    return sorted(set(assets), key=lambda item: (item.kind, item.path))


def fingerprint(asset: Asset) -> Optional[Fingerprint]:
    path = Path(asset.path)
    try:
        link_target = os.readlink(str(path)) if path.is_symlink() else None
        metadata = path.stat()
        if metadata.st_size > MAX_ASSET_BYTES:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except (OSError, ValueError):
        return None
    cdhash = signature_metadata(str(path)).cdhash if asset.kind == "loaded_macho" else None
    return Fingerprint(
        path=str(path),
        kind=asset.kind,
        sha256=digest.hexdigest(),
        size=metadata.st_size,
        mode=metadata.st_mode & 0o7777,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        link_target=link_target,
        cdhash=cdhash,
    )


def capture(assets: Iterable[Asset]) -> Tuple[List[Fingerprint], int]:
    entries = []
    skipped = 0
    for asset in assets:
        entry = fingerprint(asset)
        if entry is None:
            skipped += 1
        else:
            entries.append(entry)
    return entries, skipped


def write_baseline(path: Path, entries: List[Fingerprint], skipped: int = 0) -> Dict[str, object]:
    destination = path.expanduser().resolve()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    document = {
        "schema": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "entries": [asdict(entry) for entry in entries],
        "skipped": skipped,
    }
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(destination.parent),
            prefix=".rattler-baseline-", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(handle.name, 0o600)
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(destination))
        os.chmod(str(destination), 0o600)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    return {
        "baseline": str(destination),
        "entries": len(entries),
        "skipped": skipped,
        "created_at": document["created_at"],
    }


def create_baseline(
    path: Path,
    home: Optional[str] = None,
    launchd_roots: Optional[Sequence[Path]] = None,
    include_loaded_code: bool = True,
) -> Dict[str, object]:
    entries, skipped = capture(discover_assets(home, launchd_roots, include_loaded_code))
    return write_baseline(path, entries, skipped)


def _load(path: Path) -> List[Fingerprint]:
    destination = path.expanduser().resolve()
    if destination.stat().st_size > MAX_BASELINE_BYTES:
        raise ValueError("baseline exceeds size limit")
    with destination.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or document.get("schema") != SCHEMA_VERSION:
        raise ValueError("unsupported baseline schema")
    raw_entries = document.get("entries")
    if not isinstance(raw_entries, list) or len(raw_entries) > 100000:
        raise ValueError("invalid baseline entries")
    entries = []
    for item in raw_entries:
        if not isinstance(item, dict):
            raise ValueError("invalid baseline entry")
        entries.append(Fingerprint(**item))
    return entries


def compare_entries(expected: List[Fingerprint], current: List[Fingerprint]) -> List[Finding]:
    findings = []
    expected_by_key = {(entry.kind, entry.path): entry for entry in expected}
    current_by_key = {(entry.kind, entry.path): entry for entry in current}
    for key, old in expected_by_key.items():
        new = current_by_key.get(key)
        if new is None:
            severity = Severity.HIGH if old.kind in ("launchd_plist", "startup_executable") else Severity.MEDIUM
            findings.append(Finding(
                "RAT-BASE-001", "Baselined asset is missing", severity, "integrity",
                "A file recorded in the integrity baseline is no longer present.",
                {"path": old.path, "kind": old.kind, "expected_sha256": old.sha256},
            ))
            continue
        changed = [
            field for field in ("sha256", "size", "mode", "uid", "gid", "link_target")
            if getattr(old, field) != getattr(new, field)
        ]
        if old.cdhash is not None and old.cdhash != new.cdhash:
            changed.append("cdhash")
        if changed:
            severity = Severity.CRITICAL if old.kind == "startup_executable" else Severity.HIGH
            findings.append(Finding(
                "RAT-BASE-002", "Baselined asset changed", severity, "integrity",
                "Content or security metadata changed after the baseline was created.",
                {
                    "path": old.path, "kind": old.kind, "changed": changed,
                    "expected_sha256": old.sha256, "current_sha256": new.sha256,
                    "expected_cdhash": old.cdhash, "current_cdhash": new.cdhash,
                },
            ))
    for key, new in current_by_key.items():
        if key in expected_by_key:
            continue
        severity = Severity.HIGH if new.kind in ("launchd_plist", "startup_executable") else Severity.LOW
        findings.append(Finding(
            "RAT-BASE-003", "New asset appeared after baseline", severity, "integrity",
            "A persistence entry or loaded code image was not present in the known-good baseline.",
            {"path": new.path, "kind": new.kind, "sha256": new.sha256, "cdhash": new.cdhash},
        ))
    return findings


def check_baseline(
    path: Path,
    home: Optional[str] = None,
    launchd_roots: Optional[Sequence[Path]] = None,
    include_loaded_code: bool = True,
) -> Tuple[Check, List[Finding]]:
    try:
        expected = _load(path)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        return Check("baseline", Status.UNKNOWN, "integrity baseline unavailable", {"error": str(error)}), []
    current_assets = discover_assets(home, launchd_roots, include_loaded_code)
    current_keys = {(asset.kind, asset.path) for asset in current_assets}
    # A module can be unloaded between baseline creation and checking while its
    # file remains intact. Recheck every expected path directly, then add newly
    # discovered assets to detect drift without treating normal app exits as loss.
    for entry in expected:
        key = (entry.kind, entry.path)
        if key not in current_keys:
            current_assets.append(Asset(entry.path, entry.kind))
            current_keys.add(key)
    current, skipped = capture(current_assets)
    findings = compare_entries(expected, current)
    return Check(
        "baseline", Status.HEALTHY, "integrity baseline checked",
        {"expected": len(expected), "current": len(current), "skipped": skipped},
    ), findings
