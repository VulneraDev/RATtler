"""Bounded, source-aware macOS persistence and security-drift inventory."""

import json
import os
import platform
import plistlib
import re
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .behavior import suspicious_location
from .injection import SignatureInfo, signature_info
from .model import Check, Finding, Severity, Status
from .runner import CommandResult, run


MAX_ITEMS_PER_SOURCE = 512
MAX_RETURNED_ITEMS = 24
MAX_TOTAL_ITEMS = 2500
MAX_FILE_BYTES = 1024 * 1024
MAX_COMMAND_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 6
MAX_VISITED_PATHS_PER_SOURCE = 50000
MAX_CHILDREN_PER_DIRECTORY = 16384

SOURCE_LABELS = {
    "login_items": "Login items",
    "background_tasks": "Background task management",
    "shell_startup": "Shell startup files",
    "cron": "Cron jobs",
    "periodic": "Periodic jobs",
    "authorization_plugins": "Authorization plug-ins",
    "browser_extensions": "Browser extensions",
    "developer_extensions": "Developer-tool extensions",
    "configuration_profiles": "Configuration profiles",
    "privacy_controls": "Privacy-control state",
    "security_controls": "Security-control state",
}

FILE_SOURCES = {
    "background_tasks", "shell_startup", "cron", "periodic",
    "authorization_plugins", "browser_extensions", "developer_extensions",
    "privacy_controls",
}
SYSTEM_OWNED_SOURCES = {"cron", "periodic", "authorization_plugins"}
SHELL_NAMES = {".zshrc", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".profile"}
MANIFEST_NAMES = {"manifest.json", "package.json", "extensions.json"}
RISKY_PATH = re.compile(r"(?:^|[\s;&|()])(/(?:private/)?tmp/[^\s;&|]+|/var/tmp/[^\s;&|]+)")
PRELOAD = re.compile(r"\b(DYLD_INSERT_LIBRARIES|LD_PRELOAD)\b")


def _default_roots(home: Path) -> Dict[str, List[Path]]:
    support = home / "Library/Application Support"
    return {
        "background_tasks": [
            support / "com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
        ],
        "shell_startup": [home / item for item in sorted(SHELL_NAMES)],
        "cron": [Path("/etc/crontab"), Path("/etc/cron.d")],
        "periodic": [Path("/etc/periodic")],
        "authorization_plugins": [Path("/Library/Security/SecurityAgentPlugins")],
        "browser_extensions": [
            support / "Google/Chrome", support / "Chromium", support / "BraveSoftware/Brave-Browser",
            support / "Microsoft Edge", support / "Firefox/Profiles", home / "Library/Safari/Extensions",
        ],
        "developer_extensions": [
            home / ".vscode/extensions", home / ".cursor/extensions", home / ".windsurf/extensions",
            support / "Developer/Shared/Xcode/Plug-ins", Path("/Library/Application Support/Developer/Shared/Xcode/Plug-ins"),
        ],
        "privacy_controls": [support / "com.apple.TCC/TCC.db"],
    }


def _matches(source: str, path: Path, is_directory: bool) -> bool:
    name = path.name
    if source == "shell_startup":
        return not is_directory and name in SHELL_NAMES
    if source == "background_tasks":
        return not is_directory and name == "backgrounditems.btm"
    if source == "browser_extensions":
        return not is_directory and name in MANIFEST_NAMES
    if source == "developer_extensions":
        return path.suffix == ".xcplugin" or (not is_directory and name == "package.json")
    if source == "authorization_plugins":
        return path.suffix in (".bundle", ".plugin")
    if source == "privacy_controls":
        return not is_directory and name == "TCC.db"
    return not is_directory


def _item(path: Path, source: str, metadata: os.stat_result, is_link: bool, kind: str) -> Dict[str, object]:
    return {
        "source": source,
        "path": str(path),
        "kind": kind,
        "size": metadata.st_size,
        "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "modified_ns": metadata.st_mtime_ns,
        "symbolic_link": is_link,
    }


def _metadata_findings(item: Dict[str, object], system_owned: bool) -> List[Finding]:
    findings = []
    evidence = {key: item.get(key) for key in ("source", "path", "kind", "mode", "uid", "gid")}
    if item.get("symbolic_link") is True:
        findings.append(Finding(
            "RAT-PERSIST-101", "Persistence asset is a symbolic link", Severity.MEDIUM,
            "persistence", "A persistence-related asset redirects to another filesystem location.", evidence,
        ))
    try:
        mode = int(str(item.get("mode")), 8)
    except ValueError:
        mode = 0
    if item.get("symbolic_link") is not True and mode & (stat.S_IWGRP | stat.S_IWOTH):
        findings.append(Finding(
            "RAT-PERSIST-102", "Persistence asset is broadly writable", Severity.HIGH,
            "persistence", "Another local account or group can replace this persistence-related asset.", evidence,
        ))
    if system_owned and item.get("uid") != 0:
        findings.append(Finding(
            "RAT-PERSIST-103", "System persistence asset is not root-owned", Severity.MEDIUM,
            "persistence", "A system-level persistence location contains an item not owned by root.", evidence,
        ))
    return findings


def _walk_source(source: str, candidates: Sequence[Path]) -> Tuple[List[Dict[str, object]], List[Finding], List[str], bool]:
    items: List[Dict[str, object]] = []
    findings: List[Finding] = []
    errors: List[str] = []
    limited = False
    seen: Set[str] = set()
    visited = 0
    queue: List[Tuple[Path, int]] = [(path.expanduser(), 0) for path in candidates]
    while queue and len(items) < MAX_ITEMS_PER_SOURCE:
        if visited >= MAX_VISITED_PATHS_PER_SOURCE:
            limited = True
            break
        path, depth = queue.pop(0)
        identity = os.path.normcase(os.path.abspath(str(path)))
        if identity in seen:
            continue
        seen.add(identity)
        visited += 1
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            errors.append("%s: %s" % (path, error.strerror or error.__class__.__name__))
            continue
        is_link = stat.S_ISLNK(metadata.st_mode)
        is_directory = stat.S_ISDIR(metadata.st_mode)
        if _matches(source, path, is_directory):
            kind = "bundle" if is_directory or path.suffix in (".bundle", ".plugin", ".xcplugin") else "file"
            entry = _item(path, source, metadata, is_link, kind)
            items.append(entry)
            findings.extend(_metadata_findings(entry, source in SYSTEM_OWNED_SOURCES))
            if is_directory:
                # A bundle is one persistence object; its internal Info.plist is
                # separately returned as a baseline asset when available.
                continue
        if is_directory and not is_link and depth < MAX_DEPTH:
            try:
                children = []
                with os.scandir(str(path)) as entries:
                    for child in entries:
                        if len(children) == MAX_CHILDREN_PER_DIRECTORY:
                            limited = True
                            break
                        children.append(Path(child.path))
                children.sort()
            except OSError as error:
                errors.append("%s: %s" % (path, error.strerror or error.__class__.__name__))
                continue
            queue.extend((child, depth + 1) for child in children)
    if queue:
        limited = True
    return items, findings, errors[:8], limited


def _read_bounded(path: Path) -> Optional[bytes]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(path), flags)
        with os.fdopen(descriptor, "rb") as handle:
            payload = handle.read(MAX_FILE_BYTES + 1)
        return payload if len(payload) <= MAX_FILE_BYTES else None
    except OSError:
        return None


def _startup_findings(items: List[Dict[str, object]]) -> List[Finding]:
    findings = []
    for item in items:
        if (
            item.get("source") not in ("shell_startup", "cron")
            or item.get("symbolic_link") or not isinstance(item.get("path"), str)
        ):
            continue
        payload = _read_bounded(Path(str(item["path"])))
        if payload is None:
            continue
        text = payload.decode("utf-8", errors="replace")
        preload = sorted(set(PRELOAD.findall(text)))
        if preload:
            findings.append(Finding(
                "RAT-PERSIST-105", "Startup script configures library preloading", Severity.HIGH,
                "persistence", "A shell or cron startup source sets a process-wide library preload variable.",
                {"source": item["source"], "path": item["path"], "variables": preload},
            ))
        risky = []
        for line_number, line in enumerate(text.splitlines()[:5000], 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = RISKY_PATH.search(stripped)
            if match:
                risky.append({"line": line_number, "path": match.group(1)[:512]})
            if len(risky) == 8:
                break
        if risky:
            findings.append(Finding(
                "RAT-PERSIST-104", "Startup source references a staging path", Severity.HIGH,
                "persistence", "A shell or cron startup source references executable material in a temporary location.",
                {"source": item["source"], "path": item["path"], "references": risky},
            ))
    return findings


def _current_user_crontab() -> Tuple[List[Dict[str, object]], List[Finding], List[str]]:
    result = run(["/usr/bin/crontab", "-l"], timeout=10.0)
    if result is None:
        return [], [], ["current-user crontab command unavailable"]
    combined = (result.stdout + " " + result.stderr).lower()
    if result.returncode != 0:
        if "no crontab" in combined:
            return [], [], []
        return [], [], ["current-user crontab could not be read"]
    if len(result.stdout.encode("utf-8", errors="replace")) > MAX_COMMAND_BYTES:
        return [], [], ["current-user crontab exceeded its output limit"]
    items = []
    findings = []
    for line_number, line in enumerate(result.stdout.splitlines()[:5000], 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        preload = sorted(set(PRELOAD.findall(stripped)))
        risky = RISKY_PATH.search(stripped)
        items.append({
            "source": "cron", "kind": "current_user_crontab", "line": line_number,
            "preload_directive": bool(preload), "staging_path_reference": bool(risky),
        })
        if preload:
            findings.append(Finding(
                "RAT-PERSIST-105", "Cron job configures library preloading", Severity.HIGH,
                "persistence", "The current user's crontab sets a process-wide library preload variable.",
                {"source": "cron", "line": line_number, "variables": preload},
            ))
        if risky:
            findings.append(Finding(
                "RAT-PERSIST-104", "Cron job references a staging path", Severity.HIGH,
                "persistence", "The current user's crontab references executable material in a temporary location.",
                {"source": "cron", "line": line_number, "reference": risky.group(1)[:512]},
            ))
        if len(items) == MAX_ITEMS_PER_SOURCE:
            break
    return items, findings, []


def _manifest_context(items: List[Dict[str, object]]) -> Tuple[List[Finding], List[Dict[str, object]]]:
    findings = []
    enriched = []
    for original in items:
        item = dict(original)
        raw_path = item.get("path")
        if not isinstance(raw_path, str):
            enriched.append(item)
            continue
        path = Path(raw_path)
        if path.name not in MANIFEST_NAMES:
            enriched.append(item)
            continue
        payload = _read_bounded(path)
        try:
            document = json.loads(payload.decode("utf-8")) if payload is not None else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            document = None
        if isinstance(document, dict):
            if path.name == "extensions.json":
                addons = document.get("addons")
                item["entries"] = len(addons) if isinstance(addons, list) else 0
            else:
                for key in ("name", "version", "publisher"):
                    if isinstance(document.get(key), (str, int, float)):
                        item[key] = str(document[key])[:256]
                permissions = document.get("permissions")
                if isinstance(permissions, list):
                    item["permission_count"] = min(len(permissions), 10000)
                update_url = document.get("update_url")
                if isinstance(update_url, str):
                    item["update_url"] = update_url[:1024]
                    if update_url.lower().startswith("http://"):
                        findings.append(Finding(
                            "RAT-PERSIST-107", "Extension uses an insecure update channel", Severity.MEDIUM,
                            "persistence", "An extension manifest can retrieve updates without transport encryption.",
                            {"source": item["source"], "path": item["path"], "update_url": update_url[:1024]},
                        ))
        enriched.append(item)
    return findings, enriched


def _plugin_trust(items: List[Dict[str, object]]) -> Tuple[List[Finding], List[Dict[str, object]]]:
    candidates = [item for item in items if item.get("source") == "authorization_plugins"][:16]
    if not candidates:
        return [], items

    def inspect(item: Dict[str, object]) -> Tuple[SignatureInfo, str, Optional[bool]]:
        path = str(item["path"])
        signature = signature_info(path)
        assessment = run(["/usr/sbin/spctl", "-a", "-vv", "-t", "install", path], timeout=5.0)
        text = "" if assessment is None else (assessment.stdout + "\n" + assessment.stderr).lower()
        gatekeeper = "unavailable" if assessment is None else "accepted" if assessment.returncode == 0 else "rejected"
        notarized = None if assessment is None else "notarized" in text
        return signature, gatekeeper, notarized

    with ThreadPoolExecutor(max_workers=min(4, len(candidates))) as executor:
        contexts = list(executor.map(inspect, candidates))
    by_path = {str(item["path"]): context for item, context in zip(candidates, contexts)}
    findings = []
    enriched = []
    for original in items:
        item = dict(original)
        context = by_path.get(str(item["path"]))
        if context is not None:
            signature, gatekeeper, notarized = context
            item.update({
                "signature": signature.kind, "signature_valid": signature.valid,
                "team_id": signature.team_id, "identifier": signature.identifier,
                "cdhash": signature.cdhash, "gatekeeper_assessment": gatekeeper,
                "notarized": notarized,
            })
            if not signature.valid or signature.kind in ("unsigned", "adhoc"):
                findings.append(Finding(
                    "RAT-PERSIST-106", "Privileged authorization plug-in has invalid signing", Severity.HIGH,
                    "persistence", "An authorization plug-in failed strict code-signature validation.",
                    {"path": item["path"], "signature": signature.kind, "team_id": signature.team_id,
                     "identifier": signature.identifier, "cdhash": signature.cdhash},
                ))
        enriched.append(item)
    return findings, enriched


def _login_item_trust(items: List[Dict[str, object]]) -> Tuple[List[Finding], List[Dict[str, object]]]:
    candidates = []
    for item in items:
        raw_path = item.get("path")
        if not isinstance(raw_path, str) or ".app" not in raw_path.lower():
            continue
        path = Path(raw_path)
        if path.exists() and not path.is_symlink():
            candidates.append(item)
        if len(candidates) == 8:
            break
    if not candidates:
        return [], items

    def inspect(item: Dict[str, object]) -> Tuple[SignatureInfo, str, Optional[bool]]:
        path = str(item["path"])
        signature = signature_info(path)
        assessment = run(["/usr/sbin/spctl", "-a", "-vv", "-t", "install", path], timeout=5.0)
        text = "" if assessment is None else (assessment.stdout + "\n" + assessment.stderr).lower()
        gatekeeper = "unavailable" if assessment is None else "accepted" if assessment.returncode == 0 else "rejected"
        notarized = None if assessment is None else "notarized" in text
        return signature, gatekeeper, notarized

    with ThreadPoolExecutor(max_workers=min(4, len(candidates))) as executor:
        contexts = list(executor.map(inspect, candidates))
    by_path = {str(item["path"]): context for item, context in zip(candidates, contexts)}
    findings = []
    enriched = []
    for original in items:
        item = dict(original)
        context = by_path.get(str(item.get("path")))
        if context is not None:
            signature, gatekeeper, notarized = context
            item.update({
                "signature": signature.kind, "signature_valid": signature.valid,
                "team_id": signature.team_id, "identifier": signature.identifier,
                "cdhash": signature.cdhash, "gatekeeper_assessment": gatekeeper,
                "notarized": notarized,
            })
            if not signature.valid or signature.kind in ("unsigned", "adhoc"):
                findings.append(Finding(
                    "RAT-PERSIST-109", "Login item application has untrusted signing", Severity.MEDIUM,
                    "persistence", "An application registered to start at login failed strict code-signature validation.",
                    {"path": item["path"], "name": item.get("name"), "signature": signature.kind,
                     "team_id": signature.team_id, "identifier": signature.identifier, "cdhash": signature.cdhash},
                ))
        enriched.append(item)
    return findings, enriched


def _parse_login_items(result: Optional[CommandResult]) -> Tuple[List[Dict[str, object]], str, str]:
    if result is None or result.returncode != 0:
        return [], "degraded", "login-item inventory unavailable"
    if len(result.stdout.encode("utf-8", errors="replace")) > MAX_COMMAND_BYTES:
        return [], "degraded", "login-item inventory exceeded its output limit"
    try:
        document = json.loads(result.stdout)
    except (TypeError, ValueError):
        return [], "degraded", "login-item inventory returned invalid JSON"
    raw = document.get("SPLoginItemDataType") if isinstance(document, dict) else None
    if not isinstance(raw, list):
        raw = []
    items = []
    for entry in raw[:MAX_ITEMS_PER_SOURCE]:
        if not isinstance(entry, dict):
            continue
        item = {"source": "login_items", "kind": "login_item"}
        for source_key, output_key in (("_name", "name"), ("path", "path"), ("status", "status")):
            value = entry.get(source_key)
            if isinstance(value, str):
                item[output_key] = value[:4096]
        items.append(item)
    return items, "healthy", "login items inventoried"


def _parse_configuration_profiles(result: Optional[CommandResult]) -> Tuple[List[Dict[str, object]], str, str]:
    if result is None or result.returncode != 0:
        return [], "degraded", "configuration-profile inventory unavailable"
    payload = result.stdout.encode("utf-8", errors="replace")
    if len(payload) > MAX_COMMAND_BYTES:
        return [], "degraded", "configuration-profile inventory exceeded its output limit"
    try:
        document = plistlib.loads(payload)
    except (TypeError, ValueError, plistlib.InvalidFileException):
        return [], "degraded", "configuration-profile inventory returned invalid data"
    if not isinstance(document, dict):
        return [], "degraded", "configuration-profile inventory returned an unexpected shape"

    field_names = {
        "profiledisplayname": "name", "payloaddisplayname": "name",
        "profileidentifier": "identifier", "payloadidentifier": "identifier",
        "profileuuid": "uuid", "payloaduuid": "uuid",
        "profileorganization": "organization", "payloadorganization": "organization",
        "profileinstalldate": "installed_at", "installationdate": "installed_at",
    }

    def dictionaries(value: object, depth: int = 0) -> Iterable[Dict[str, object]]:
        if depth > 3:
            return
        if isinstance(value, list):
            for entry in value[:MAX_ITEMS_PER_SOURCE]:
                yield from dictionaries(entry, depth + 1)
        elif isinstance(value, dict):
            normalized = {str(key).replace("_", "").lower() for key in value}
            if normalized.intersection(field_names):
                yield value
            else:
                for entry in list(value.values())[:MAX_ITEMS_PER_SOURCE]:
                    yield from dictionaries(entry, depth + 1)

    items = []
    for top_key, value in list(document.items())[:MAX_ITEMS_PER_SOURCE]:
        scope = "device" if str(top_key).lower() in ("_computerlevel", "computerlevel") else "user"
        for entry in dictionaries(value):
            item: Dict[str, object] = {
                "source": "configuration_profiles", "kind": "configuration_profile", "scope": scope,
            }
            for key, value in entry.items():
                output_key = field_names.get(str(key).replace("_", "").lower())
                if output_key and isinstance(value, (str, int, float)):
                    item[output_key] = str(value)[:512]
            items.append(item)
            if len(items) == MAX_ITEMS_PER_SOURCE:
                return items, "healthy", "configuration profiles inventoried"
    return items, "healthy", "configuration profiles inventoried"


def _command_sources() -> Tuple[List[Dict[str, object]], List[Finding]]:
    sources = []
    findings = []
    login_result = run([
        "/usr/sbin/system_profiler", "SPLoginItemDataType", "-json", "-detailLevel", "mini",
    ], timeout=20.0)
    login_items, status, message = _parse_login_items(login_result)
    trust_findings, login_items = _login_item_trust(login_items)
    findings.extend(trust_findings)
    login_limited = len(login_items) >= MAX_ITEMS_PER_SOURCE
    if login_limited and status == "healthy":
        status = "degraded"
        message = "login-item inventory reached its safety limit"
    for item in login_items:
        path = item.get("path")
        reason = suspicious_location(path) if isinstance(path, str) else None
        if reason:
            findings.append(Finding(
                "RAT-PERSIST-108", "Login item launches from a risky location", Severity.HIGH,
                "persistence", "A registered login item points into a staging location.",
                {"path": path, "name": item.get("name"), "reason": reason},
            ))
    sources.append({
        "id": "login_items", "label": SOURCE_LABELS["login_items"], "status": status,
        "message": message, "count": len(login_items), "limited": login_limited,
        "items": login_items[:MAX_RETURNED_ITEMS], "errors": [],
    })

    profile = run(["/usr/bin/profiles", "status", "-type", "enrollment"], timeout=10.0)
    profile_list = run([
        "/usr/bin/profiles", "list", "-type", "configuration", "-output", "stdout-xml",
    ], timeout=10.0)
    profile_items, profile_status, _profile_message = _parse_configuration_profiles(profile_list)
    enrollment_ok = profile is not None and profile.returncode == 0
    profile_text = (profile.stdout + " " + profile.stderr).strip()[:1024] if profile else ""
    profile_limited = len(profile_items) >= MAX_ITEMS_PER_SOURCE
    if enrollment_ok and not profile_limited:
        profile_items.append({
            "source": "configuration_profiles", "kind": "enrollment_state", "state": profile_text,
        })
    profile_ok = enrollment_ok and profile_status == "healthy" and not profile_limited
    sources.append({
        "id": "configuration_profiles", "label": SOURCE_LABELS["configuration_profiles"],
        "status": "healthy" if profile_ok else "degraded",
        "message": "configuration profiles and enrollment state collected" if profile_ok else
        "configuration-profile inventory reached its safety limit" if profile_limited else
        "configuration-profile coverage is partial",
        "count": len(profile_items), "limited": profile_limited,
        "items": profile_items[:MAX_RETURNED_ITEMS],
        "errors": [] if profile_ok else ["profile inventory or enrollment state unavailable"],
    })

    controls = []
    commands = (
        ("system_integrity_protection", ["/usr/bin/csrutil", "status"]),
        ("application_firewall", ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]),
        ("filevault", ["/usr/bin/fdesetup", "status"]),
    )
    failures = []
    for name, command in commands:
        result = run(command, timeout=10.0)
        if result is None or result.returncode != 0:
            failures.append(name)
            continue
        controls.append({"source": "security_controls", "kind": name, "state": (result.stdout + " " + result.stderr).strip()[:512]})
    sources.append({
        "id": "security_controls", "label": SOURCE_LABELS["security_controls"],
        "status": "healthy" if not failures else "degraded",
        "message": "security-control state collected" if not failures else "some security-control state is unavailable",
        "count": len(controls), "limited": False, "items": controls, "errors": failures,
    })
    return sources, findings


def collect_atlas(
    home: Optional[Path] = None,
    source_roots: Optional[Dict[str, Sequence[Path]]] = None,
    include_commands: Optional[bool] = None,
) -> Tuple[List[Dict[str, object]], List[Finding], List[Tuple[str, str]]]:
    endpoint_home = Path(home or Path.home())
    roots = {key: list(value) for key, value in (source_roots or _default_roots(endpoint_home)).items()}
    run_commands = (source_roots is None) if include_commands is None else include_commands
    sources = []
    findings: List[Finding] = []
    assets: List[Tuple[str, str]] = []
    total = 0
    for source in SOURCE_LABELS:
        if source not in FILE_SOURCES or source not in roots:
            continue
        remaining = max(0, MAX_TOTAL_ITEMS - total)
        if remaining == 0:
            items, source_findings, errors, limited = [], [], [], True
        else:
            items, source_findings, errors, limited = _walk_source(source, roots[source])
            if len(items) > remaining:
                items, limited = items[:remaining], True
        if source == "cron" and run_commands:
            cron_items, cron_findings, cron_errors = _current_user_crontab()
            available = max(0, MAX_ITEMS_PER_SOURCE - len(items), remaining - len(items))
            if len(cron_items) > available:
                limited = True
            items.extend(cron_items[:available])
            source_findings.extend(cron_findings)
            errors.extend(cron_errors)
        total += len(items)
        findings.extend(source_findings)
        manifest_findings, items = _manifest_context(items)
        findings.extend(manifest_findings)
        if source == "authorization_plugins" and run_commands:
            plugin_findings, items = _plugin_trust(items)
            findings.extend(plugin_findings)
        findings.extend(_startup_findings(items))
        for item in items:
            raw_path = item.get("path")
            if not isinstance(raw_path, str):
                continue
            path = Path(raw_path)
            if (
                item.get("kind") == "file" and item.get("symbolic_link") is not True
                and source != "privacy_controls" and int(item.get("size", 0)) <= MAX_FILE_BYTES
            ):
                assets.append((str(path), "atlas_" + source))
            elif item.get("symbolic_link") is not True and source in ("authorization_plugins", "developer_extensions"):
                info = path / "Contents/Info.plist"
                if info.is_file() and not info.is_symlink():
                    assets.append((str(info), "atlas_" + source))
        status = "degraded" if errors or limited else "healthy"
        message = "source inventory collected"
        if errors:
            message = "source inventory is partially unavailable"
        elif limited:
            message = "source inventory reached its safety limit"
        sources.append({
            "id": source, "label": SOURCE_LABELS[source], "status": status,
            "message": message, "count": len(items), "limited": limited,
            "items": items[:MAX_RETURNED_ITEMS], "errors": errors,
        })
    if run_commands:
        command_sources, command_findings = _command_sources()
        sources.extend(command_sources)
        findings.extend(command_findings)
    return sources, findings, sorted(set(assets), key=lambda item: (item[1], item[0]))


def persistence_atlas_sensor(
    home: Optional[Path] = None,
    source_roots: Optional[Dict[str, Sequence[Path]]] = None,
    include_commands: Optional[bool] = None,
) -> Tuple[Check, List[Finding]]:
    if platform.system() != "Darwin" and source_roots is None:
        return Check("persistence_atlas", Status.UNKNOWN, "Persistence Atlas is macOS-only"), []
    sources, findings, assets = collect_atlas(home, source_roots, include_commands)
    degraded = [item["id"] for item in sources if item["status"] != "healthy"]
    if not sources:
        status = Status.UNKNOWN
        message = "no persistence sources were available"
    elif degraded:
        status = Status.DEGRADED
        message = "persistence inventory coverage is partial"
    else:
        status = Status.HEALTHY
        message = "persistence sources inventoried"
    return Check(
        "persistence_atlas", status, message,
        {
            "sources": sources,
            "sources_checked": len(sources),
            "sources_healthy": len(sources) - len(degraded),
            "sources_degraded": degraded,
            "items": sum(int(item["count"]) for item in sources),
            "baseline_assets": len(assets),
            "limits": {
                "items_per_source": MAX_ITEMS_PER_SOURCE, "total_items": MAX_TOTAL_ITEMS,
                "returned_items_per_source": MAX_RETURNED_ITEMS, "file_bytes": MAX_FILE_BYTES,
                "command_bytes": MAX_COMMAND_BYTES, "depth": MAX_DEPTH,
                "visited_paths_per_source": MAX_VISITED_PATHS_PER_SOURCE,
                "children_per_directory": MAX_CHILDREN_PER_DIRECTORY,
            },
        },
    ), findings


def discover_atlas_assets(
    home: Optional[Path] = None,
    source_roots: Optional[Dict[str, Sequence[Path]]] = None,
) -> Tuple[List[Tuple[str, str]], Set[str]]:
    if platform.system() != "Darwin" and source_roots is None:
        return [], set()
    sources, _findings, assets = collect_atlas(home, source_roots, include_commands=False)
    unavailable = {"atlas_" + str(item["id"]) for item in sources if item["status"] != "healthy"}
    return assets, unavailable
