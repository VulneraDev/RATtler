"""macOS loaded-image integrity sensor.

The sensor uses lsof's machine-readable output to inventory file-backed text
mappings. It reads only the four-byte file magic needed to distinguish Mach-O
images, then asks the operating system to verify code signatures for candidates
loaded from user-writable locations.
"""

import platform
import posixpath
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .behavior import ProcessInfo, suspicious_location, trusted_system_location
from .model import Check, Finding, Severity, Status
from .runner import run


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}


@dataclass(frozen=True)
class LoadedImage:
    pid: int
    process: str
    path: str


@dataclass(frozen=True)
class SignatureInfo:
    valid: bool
    kind: str
    team_id: Optional[str] = None
    identifier: Optional[str] = None


def parse_loaded_images(output: str) -> List[LoadedImage]:
    images = []
    seen = set()
    pid = None
    process = "unknown"
    descriptor = None
    file_type = None
    for line in output.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            pid = int(line[1:])
            process = "unknown"
            descriptor = None
            file_type = None
        elif line.startswith("c"):
            process = line[1:]
        elif line.startswith("f"):
            descriptor = line[1:]
            file_type = None
        elif line.startswith("t"):
            file_type = line[1:]
        elif line.startswith("n") and pid is not None and descriptor == "txt" and file_type == "REG":
            image = LoadedImage(pid, process, line[1:])
            if image not in seen:
                images.append(image)
                seen.add(image)
    return images


def is_macho(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(4) in MACHO_MAGICS
    except OSError:
        return False


def signature_metadata(path: str) -> SignatureInfo:
    details = run(["/usr/bin/codesign", "-d", "--verbose=4", path], timeout=5.0)
    output = "" if details is None else details.stdout + "\n" + details.stderr
    fields = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip()
    signature = fields.get("Signature", "")
    has_authority = "Authority" in fields
    has_platform_signature = "Platform identifier" in fields
    if details is None or details.returncode != 0:
        kind = "unsigned"
    elif signature.lower() == "adhoc":
        kind = "adhoc"
    elif has_authority or has_platform_signature or fields.get("TeamIdentifier") not in (None, "not set"):
        kind = "signed"
    else:
        kind = "adhoc"
    return SignatureInfo(
        valid=bool(details and details.returncode == 0),
        kind=kind,
        team_id=fields.get("TeamIdentifier") if fields.get("TeamIdentifier") != "not set" else None,
        identifier=fields.get("Identifier"),
    )


def verify_signature(path: str) -> bool:
    result = run(
        ["/usr/bin/codesign", "--verify", "--strict", "--ignore-resources", "--verbose=2", path],
        timeout=5.0,
    )
    return bool(result and result.returncode == 0)


def signature_info(path: str) -> SignatureInfo:
    """Return signature metadata with full code-object verification."""
    metadata = signature_metadata(path)
    return SignatureInfo(
        valid=verify_signature(path),
        kind=metadata.kind,
        team_id=metadata.team_id,
        identifier=metadata.identifier,
    )


def _user_writable_location(path: str, home: Optional[str]) -> bool:
    user_home = posixpath.normpath(posixpath.abspath(home or str(Path.home())))
    real_path = posixpath.normpath(posixpath.abspath(path))
    try:
        if posixpath.commonpath((real_path, user_home)) == user_home:
            return True
    except ValueError:
        pass
    return real_path.startswith(("/private/tmp/", "/tmp/", "/var/tmp/", "/private/var/folders/"))


def _eligible_host(path: str) -> bool:
    name = posixpath.basename(path).lower()
    interpreters = ("python", "ruby", "perl", "node", "java", "bash", "zsh", "sh", "osascript")
    if any(name == item or name.startswith(item) for item in interpreters):
        return False
    return (
        trusted_system_location(path)
        or path.startswith("/Applications/")
        or ".app/Contents/MacOS/" in path
    )


def _plausible_code_path(path: str, location_reason: Optional[str]) -> bool:
    if location_reason:
        return True
    lowered = path.lower()
    return (
        lowered.endswith((".dylib", ".so"))
        or ".framework/" in lowered
        or ".bundle/contents/macos/" in lowered
        or ".appex/contents/macos/" in lowered
        or ".app/contents/macos/" in lowered
    )


def _app_bundle_root(path: str) -> Optional[str]:
    lowered = path.lower()
    marker = ".app/"
    position = lowered.find(marker)
    if position < 0:
        return None
    return posixpath.normpath(path[:position + len(".app")])


def analyze_loaded_images(
    images: List[LoadedImage],
    processes: Dict[int, ProcessInfo],
    home: Optional[str] = None,
) -> Tuple[List[Finding], int]:
    findings = []
    candidates = []
    eligible_pids: Dict[int, bool] = {}
    for image in images:
        host = processes.get(image.pid)
        if not host:
            continue
        eligible = eligible_pids.get(image.pid)
        if eligible is None:
            eligible = _eligible_host(host.executable)
            eligible_pids[image.pid] = eligible
        if not eligible:
            continue
        clean_path = image.path[:-10] if image.path.endswith(" (deleted)") else image.path
        if posixpath.normpath(clean_path) == posixpath.normpath(host.executable):
            continue
        if image.path.endswith(" (deleted)"):
            findings.append(Finding(
                "RAT-INJECT-002", "Deleted executable image remains loaded", Severity.CRITICAL,
                "injection", "A trusted process retains a mapped image whose backing file was deleted.",
                {"pid": image.pid, "process": image.process, "host": host.executable, "image": image.path},
            ))
            continue
        if not _user_writable_location(clean_path, home):
            continue
        host_bundle = _app_bundle_root(host.executable)
        image_bundle = _app_bundle_root(clean_path)
        if host_bundle and image_bundle and host_bundle == image_bundle:
            # Nested app frameworks are expected mappings. Detecting in-place
            # tampering requires a persistent hash baseline, planned separately.
            continue
        reason = suspicious_location(clean_path, home)
        if not _plausible_code_path(clean_path, reason) or not is_macho(clean_path):
            continue
        candidates.append((image, host, clean_path, reason))

    signature_paths = sorted({
        path for _image, host, module, _reason in candidates
        for path in (module, host.executable)
    })
    signatures: Dict[str, SignatureInfo] = {}
    if signature_paths:
        with ThreadPoolExecutor(max_workers=min(8, len(signature_paths))) as executor:
            signatures = dict(zip(signature_paths, executor.map(signature_metadata, signature_paths)))

    verification_paths = []
    for _image, host, clean_path, reason in candidates:
        module_signature = signatures[clean_path]
        host_signature = signatures[host.executable]
        mismatched_team = bool(
            module_signature.team_id and host_signature.team_id
            and module_signature.team_id != host_signature.team_id
        )
        if reason or module_signature.kind in ("unsigned", "adhoc") or mismatched_team:
            verification_paths.append(clean_path)
    verification_paths = sorted(set(verification_paths))
    verified: Dict[str, bool] = {}
    if verification_paths:
        with ThreadPoolExecutor(max_workers=min(8, len(verification_paths))) as executor:
            verified = dict(zip(verification_paths, executor.map(verify_signature, verification_paths)))

    for image, host, clean_path, reason in candidates:
        module_signature = signatures[clean_path]
        host_signature = signatures[host.executable]
        mismatched_team = bool(
            module_signature.team_id and host_signature.team_id
            and module_signature.team_id != host_signature.team_id
        )
        invalid = (
            module_signature.kind in ("unsigned", "adhoc")
            or not verified.get(clean_path, True)
        )
        if not reason and not invalid and not mismatched_team:
            continue
        severity = Severity.HIGH if invalid or mismatched_team else Severity.MEDIUM
        findings.append(Finding(
            "RAT-INJECT-003",
            "Untrusted image loaded into a protected process",
            severity,
            "injection",
            "A protected process maps Mach-O code from a user-writable location.",
            {
                "pid": image.pid,
                "process": image.process,
                "host": host.executable,
                "image": clean_path,
                "location_reason": reason,
                "signature": module_signature.kind,
                "signature_valid": verified.get(clean_path),
                "module_team_id": module_signature.team_id,
                "host_team_id": host_signature.team_id,
                "team_mismatch": mismatched_team,
            },
        ))
    return findings, len(candidates)


def loaded_image_sensor(
    processes: Dict[int, ProcessInfo], home: Optional[str] = None
) -> Tuple[Check, List[Finding]]:
    if platform.system() != "Darwin":
        return Check("loaded_images", Status.UNKNOWN, "loaded-image sensor is macOS-only"), []
    result = run(["/usr/sbin/lsof", "-nP", "-Fpcftn", "-d", "txt"], timeout=15.0)
    if result is None or result.returncode not in (0, 1):
        return Check("loaded_images", Status.UNKNOWN, "loaded-image inventory unavailable"), []
    images = parse_loaded_images(result.stdout)
    findings, inspected = analyze_loaded_images(images, processes, home)
    return Check(
        "loaded_images",
        Status.HEALTHY,
        "file-backed executable mappings inspected",
        {"mappings": len(images), "user_writable_candidates": inspected},
    ), findings
