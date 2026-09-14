"""Narrow, expiring finding exceptions with cryptographic identity binding."""

import argparse
import json
import ntpath
import os
import posixpath
import re
import stat
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import Check, Event, Finding, Severity, Status


SCHEMA_VERSION = 1
MAX_POLICY_BYTES = 1024 * 1024
MAX_ENTRIES = 1000
MAX_VALIDITY_DAYS = 90
RULE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HEX_PATTERN = re.compile(r"^[0-9a-f]+$")
ENTRY_PATTERN = re.compile(r"^[0-9a-f]{32}$")
MATCH_KEYS = {"path", "cdhash", "sha256", "team_id", "identifier"}
PATH_EVIDENCE = ("path", "image", "executable", "actor_path", "plist")
CDHASH_EVIDENCE = ("cdhash", "current_cdhash", "module_cdhash", "actor_cdhash", "target_cdhash")
SHA256_EVIDENCE = ("sha256", "current_sha256")
TEAM_EVIDENCE = ("team_id", "module_team_id", "actor_team_id", "target_team_id")
IDENTIFIER_EVIDENCE = ("identifier", "module_identifier", "actor_identifier", "target_identifier")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("exception timestamps must be strings")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("exception timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _hex(value: str, lengths: Tuple[int, ...], label: str) -> str:
    normalized = value.lower()
    if len(normalized) not in lengths or not HEX_PATTERN.fullmatch(normalized):
        raise ValueError("%s has an invalid format" % label)
    return normalized


def _canonical_path(path: str) -> str:
    """Normalize either a native Windows path or an absolute POSIX path."""
    if ntpath.isabs(path) and not posixpath.isabs(path):
        return ntpath.normcase(ntpath.normpath(path))
    if posixpath.isabs(path):
        return os.path.realpath(path) if os.name != "nt" else posixpath.normpath(path)
    raise ValueError("exceptions require an absolute path")


def validate_match(match: Dict[str, object]) -> Dict[str, str]:
    if not isinstance(match, dict) or not match or set(match) - MATCH_KEYS:
        raise ValueError("exception match fields are invalid")
    normalized = {}
    for key, raw in match.items():
        if not isinstance(raw, str) or not raw or len(raw) > 4096:
            raise ValueError("exception %s must be a non-empty string" % key)
        normalized[key] = raw
    path = normalized.get("path")
    if not path:
        raise ValueError("exceptions require an absolute path")
    normalized["path"] = _canonical_path(path)
    if "cdhash" in normalized:
        normalized["cdhash"] = _hex(normalized["cdhash"], (40, 64), "CDHash")
    if "sha256" in normalized:
        normalized["sha256"] = _hex(normalized["sha256"], (64,), "SHA-256")
    strong_hash = "cdhash" in normalized or "sha256" in normalized
    signed_identity = bool(normalized.get("team_id") and normalized.get("identifier"))
    if not strong_hash and not signed_identity:
        raise ValueError("exceptions require a CDHash, SHA-256, or Team ID plus signing identifier")
    return normalized


def _validate_entry(raw: object) -> Dict[str, object]:
    if not isinstance(raw, dict):
        raise ValueError("exception entries must be objects")
    identifier = raw.get("id")
    rule_id = raw.get("rule_id")
    reason = raw.get("reason")
    if not isinstance(identifier, str) or not ENTRY_PATTERN.fullmatch(identifier):
        raise ValueError("exception ID is invalid")
    if not isinstance(rule_id, str) or not RULE_PATTERN.fullmatch(rule_id):
        raise ValueError("exception rule ID is invalid")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise ValueError("exception reason is invalid")
    created = _timestamp(raw.get("created_at"))
    expires = _timestamp(raw.get("expires_at"))
    if expires <= created or expires - created > timedelta(days=MAX_VALIDITY_DAYS, minutes=1):
        raise ValueError("exception validity must be between zero and 90 days")
    return {
        "id": identifier,
        "rule_id": rule_id,
        "match": validate_match(raw.get("match", {})),
        "reason": reason.strip(),
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat(),
    }


def load_policy(path: Path) -> List[Dict[str, object]]:
    requested = path.expanduser()
    if requested.is_symlink():
        raise ValueError("exception policy must not be a symbolic link")
    destination = requested.resolve()
    if not destination.exists():
        return []
    metadata = destination.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_POLICY_BYTES:
        raise ValueError("exception policy is unsafe or exceeds its size limit")
    if os.name != "nt" and (
        metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
    ):
        raise ValueError("exception policy must be owned by this user and mode 0600")
    with destination.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or document.get("schema") != SCHEMA_VERSION:
        raise ValueError("unsupported exception-policy schema")
    raw_entries = document.get("entries")
    if not isinstance(raw_entries, list) or len(raw_entries) > MAX_ENTRIES:
        raise ValueError("invalid exception-policy entries")
    entries = [_validate_entry(item) for item in raw_entries]
    if len({item["id"] for item in entries}) != len(entries):
        raise ValueError("duplicate exception IDs")
    return entries


def write_policy(path: Path, entries: List[Dict[str, object]]) -> None:
    if len(entries) > MAX_ENTRIES:
        raise ValueError("exception policy contains too many entries")
    requested = path.expanduser()
    if requested.is_symlink():
        raise ValueError("refusing to replace a symbolic-link policy")
    destination = requested.resolve()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    document = {"schema": SCHEMA_VERSION, "entries": [_validate_entry(item) for item in entries]}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(destination.parent),
            prefix=".rattler-exceptions-", delete=False,
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


def _evidence_values(evidence: Dict[str, object], keys: Iterable[str]) -> set:
    return {evidence.get(key) for key in keys if isinstance(evidence.get(key), str)}


def _matches(entry: Dict[str, object], rule_id: str, evidence: Dict[str, object]) -> bool:
    if entry["rule_id"] != rule_id:
        return False
    match = entry["match"]
    sources = {
        "path": set(),
        "cdhash": {value.lower() for value in _evidence_values(evidence, CDHASH_EVIDENCE)},
        "sha256": {value.lower() for value in _evidence_values(evidence, SHA256_EVIDENCE)},
        "team_id": _evidence_values(evidence, TEAM_EVIDENCE),
        "identifier": _evidence_values(evidence, IDENTIFIER_EVIDENCE),
    }
    for value in _evidence_values(evidence, PATH_EVIDENCE):
        try:
            sources["path"].add(_canonical_path(value))
        except ValueError:
            pass
    return all(value in sources[key] for key, value in match.items())


def apply_exceptions(
    path: Path,
    findings: List[Finding],
    events: List[Event],
    now: Optional[datetime] = None,
) -> Tuple[Check, List[Finding], List[Event]]:
    observed = (now or _utcnow()).astimezone(timezone.utc)
    try:
        entries = load_policy(path)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        return (
            Check("exceptions", Status.UNKNOWN, "finding exceptions unavailable", {"error": str(error)}),
            findings,
            events,
        )
    active = [entry for entry in entries if _timestamp(entry["expires_at"]) > observed]
    retained = []
    suppressed_event_ids = set()
    suppressed = []
    for finding in findings:
        exception = next((item for item in active if _matches(item, finding.rule_id, finding.evidence)), None)
        if exception is None:
            retained.append(finding)
            continue
        suppressed.append(exception["id"])
        source = finding.evidence.get("source_event")
        if isinstance(source, str):
            suppressed_event_ids.add(source)
        sources = finding.evidence.get("source_events")
        if isinstance(sources, list):
            suppressed_event_ids.update(item for item in sources if isinstance(item, str))
    adjusted_events = []
    for event in events:
        exception = next((
            item for item in active
            if isinstance(event.evidence.get("rule_id"), str)
            and _matches(item, event.evidence["rule_id"], event.evidence)
        ), None)
        if event.event_id in suppressed_event_ids or exception is not None:
            evidence = dict(event.evidence)
            evidence["reviewed_exception"] = exception["id"] if exception else "linked-finding"
            adjusted_events.append(Event(
                event.event_id, event.event_type, Severity.INFO,
                event.observed_at, evidence,
            ))
        else:
            adjusted_events.append(event)
    return (
        Check(
            "exceptions", Status.HEALTHY, "reviewed finding exceptions applied",
            {
                "active": len(active), "expired": len(entries) - len(active),
                "suppressed_findings": len(suppressed),
                "policy": str(path.expanduser().resolve()),
            },
        ),
        retained,
        adjusted_events,
    )


def add_exception(
    path: Path,
    rule_id: str,
    match: Dict[str, object],
    reason: str,
    days: int = 30,
    apply: bool = False,
) -> Dict[str, object]:
    if not RULE_PATTERN.fullmatch(rule_id or ""):
        raise ValueError("rule ID is invalid")
    if not reason or not reason.strip() or len(reason) > 500:
        raise ValueError("a concise exception reason is required")
    if days <= 0 or days > MAX_VALIDITY_DAYS:
        raise ValueError("exception duration must be between 1 and 90 days")
    normalized = validate_match(match)
    created = _utcnow()
    entry = {
        "id": uuid.uuid4().hex,
        "rule_id": rule_id,
        "match": normalized,
        "reason": reason.strip(),
        "created_at": created.isoformat(),
        "expires_at": (created + timedelta(days=days)).isoformat(),
    }
    entries = load_policy(path)
    duplicate = next((item for item in entries if item["rule_id"] == rule_id and item["match"] == normalized), None)
    if duplicate:
        raise ValueError("an exception already exists for this exact rule and identity")
    if apply:
        write_policy(path, entries + [entry])
    return {"applied": apply, "policy": str(path.expanduser().resolve()), "entry": entry}


def remove_exception(path: Path, identifier: str, apply: bool = False) -> Dict[str, object]:
    if not ENTRY_PATTERN.fullmatch(identifier or ""):
        raise ValueError("exception ID is invalid")
    entries = load_policy(path)
    target = next((item for item in entries if item["id"] == identifier), None)
    if target is None:
        raise ValueError("exception ID was not found")
    if apply:
        write_policy(path, [item for item in entries if item["id"] != identifier])
    return {"applied": apply, "policy": str(path.expanduser().resolve()), "entry": target}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rattler exceptions",
        description="Manage narrow, expiring finding exceptions.",
    )
    parser.add_argument("--policy", type=Path, default=Path.home() / ".rattler/exceptions.json")
    parser.add_argument("--pretty", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list")
    listing.add_argument("--include-expired", action="store_true")
    add = commands.add_parser("add")
    add.add_argument("--rule-id", required=True)
    add.add_argument("--path", required=True)
    add.add_argument("--cdhash")
    add.add_argument("--sha256")
    add.add_argument("--team-id")
    add.add_argument("--identifier")
    add.add_argument("--reason", required=True)
    add.add_argument("--days", type=int, default=30)
    add.add_argument("--apply", action="store_true")
    remove = commands.add_parser("remove")
    remove.add_argument("id")
    remove.add_argument("--apply", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            entries = load_policy(args.policy)
            now = _utcnow()
            if not args.include_expired:
                entries = [item for item in entries if _timestamp(item["expires_at"]) > now]
            result = {"policy": str(args.policy.expanduser().resolve()), "entries": entries}
        elif args.command == "add":
            match = {
                key: value for key, value in {
                    "path": args.path, "cdhash": args.cdhash, "sha256": args.sha256,
                    "team_id": args.team_id, "identifier": args.identifier,
                }.items() if value
            }
            result = add_exception(args.policy, args.rule_id, match, args.reason, args.days, args.apply)
        else:
            result = remove_exception(args.policy, args.id, args.apply)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(json.dumps({"error": "exception operation refused", "detail": str(error)}), file=os.sys.stderr)
        return 2
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
