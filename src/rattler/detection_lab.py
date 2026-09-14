"""Safe, deterministic detection replay and attack-chain construction."""

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .events import correlate
from .model import Event, Finding, Severity
from .native_bridge import correlate_native


SCHEMA_VERSION = 1
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_FIXTURES = 64
MAX_EVENTS = 500
MAX_EVIDENCE_BYTES = 32 * 1024
MAX_EVIDENCE_DEPTH = 5
MAX_STRING_LENGTH = 4096
EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
FIXTURE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
RULE_ID = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,127}$")
ALLOWED_EVENT_TYPES = {
    "process_started", "connection_established", "listener_opened",
    "persistence_added", "persistence_changed", "loaded_image_added",
    "loaded_image_identity_changed", "native_get_task",
    "native_get_task_read", "native_get_task_inspect",
    "native_remote_thread_create", "ransomware_canary_changed",
    "ransomware_extension_burst", "ransomware_rewrite_burst",
    "ransomware_note_created", "ransomware_deletion_burst",
}
PROCESS_EVENT_TYPES = {
    "process_started", "connection_established", "listener_opened",
    "loaded_image_added", "loaded_image_identity_changed",
}
FORBIDDEN_EVIDENCE_KEYS = {
    "payload", "payload_bytes", "binary", "content", "contents", "script",
    "shell_command", "command", "base64", "executable_bytes",
}

# A mapping is useful investigation context, not a claim that a fixture or alert
# proves malicious use of a technique.
ATTACK_RULES = {
    "RAT-NATIVE-006": ("T1055", "Process Injection"),
    "RAT-RANSOM-001": ("T1486", "Data Encrypted for Impact"),
    "RAT-RANSOM-002": ("T1486", "Data Encrypted for Impact"),
    "RAT-RANSOM-100": ("T1486", "Data Encrypted for Impact"),
    "RAT-RANSOM-101": ("T1486", "Data Encrypted for Impact"),
}


def _validate_json_value(value: object, depth: int = 0, key: str = "") -> None:
    if depth > MAX_EVIDENCE_DEPTH:
        raise ValueError("event evidence exceeds nesting limit")
    if key.lower() in FORBIDDEN_EVIDENCE_KEYS:
        raise ValueError("executable or payload content is not allowed in fixtures")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("event evidence numbers must be finite")
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValueError("event evidence string exceeds length limit")
        return
    if isinstance(value, list):
        if len(value) > 128:
            raise ValueError("event evidence list exceeds item limit")
        for item in value:
            _validate_json_value(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 64:
            raise ValueError("event evidence object exceeds key limit")
        for child_key, child in value.items():
            if not isinstance(child_key, str):
                raise ValueError("event evidence keys must be strings")
            _validate_json_value(child, depth + 1, child_key)
        return
    raise ValueError("event evidence contains an unsupported value")


def _parse_timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("event observed_at must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("event observed_at is not valid ISO-8601") from None
    if parsed.tzinfo is None:
        raise ValueError("event observed_at must include a timezone")
    return parsed.isoformat()


def _strict_object(pairs: List[Tuple[str, object]]) -> Dict[str, object]:
    document: Dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("fixture contains a duplicate JSON key: %s" % key)
        document[key] = value
    return document


def load_fixture(path: Path) -> Tuple[Dict[str, object], List[Event]]:
    source = path.expanduser()
    if source.is_symlink() or not source.is_file():
        raise ValueError("fixture must be a regular, non-symbolic-link JSON file")
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(source), flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError("fixture must be a regular, non-symbolic-link JSON file")
            payload = handle.read(MAX_FIXTURE_BYTES + 1)
        if len(payload) > MAX_FIXTURE_BYTES:
            raise ValueError("fixture exceeds the 1 MiB size limit")
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError("fixture contains a non-finite number: %s" % value)),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("fixture could not be read: %s" % error) from None
    if not isinstance(document, dict) or document.get("schema") != SCHEMA_VERSION:
        raise ValueError("unsupported detection-fixture schema")
    if set(document) - {"schema", "id", "title", "description", "safety", "window_seconds", "events", "expected"}:
        raise ValueError("fixture contains unsupported top-level fields")
    if document.get("safety") != "synthetic-no-executable-content":
        raise ValueError("fixture must declare synthetic-no-executable-content safety")
    fixture_id = document.get("id")
    if not isinstance(fixture_id, str) or not FIXTURE_ID.fullmatch(fixture_id):
        raise ValueError("fixture id must be a lowercase slug")
    for field in ("title", "description"):
        value = document.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 500:
            raise ValueError("fixture %s must be a short non-empty string" % field)
    raw_events = document.get("events")
    if not isinstance(raw_events, list) or not raw_events or len(raw_events) > MAX_EVENTS:
        raise ValueError("fixture must contain between 1 and %d events" % MAX_EVENTS)
    window_seconds = document.get("window_seconds", 900)
    if type(window_seconds) is not int or window_seconds < 1 or window_seconds > 3600:
        raise ValueError("fixture window_seconds must be between 1 and 3600")
    events = []
    seen: Set[str] = set()
    for raw in raw_events:
        if not isinstance(raw, dict) or set(raw) != {
            "event_id", "event_type", "severity", "observed_at", "evidence",
        }:
            raise ValueError("each fixture event must use the documented fields")
        identity = raw.get("event_id")
        if not isinstance(identity, str) or not EVENT_ID.fullmatch(identity) or identity in seen:
            raise ValueError("fixture event ids must be unique stable identifiers")
        seen.add(identity)
        event_type = raw.get("event_type")
        if event_type not in ALLOWED_EVENT_TYPES:
            raise ValueError("unsupported fixture event type: %s" % event_type)
        evidence = raw.get("evidence")
        if not isinstance(evidence, dict):
            raise ValueError("fixture event evidence must be an object")
        _validate_json_value(evidence)
        if len(json.dumps(evidence, sort_keys=True).encode("utf-8")) > MAX_EVIDENCE_BYTES:
            raise ValueError("event evidence exceeds size limit")
        if event_type in PROCESS_EVENT_TYPES:
            if type(evidence.get("pid")) is not int or not 0 <= evidence["pid"] <= 4294967295:
                raise ValueError("process-scoped events require a non-negative integer pid")
            if not isinstance(evidence.get("process_instance"), str) or not evidence["process_instance"]:
                raise ValueError("process-scoped events require process_instance")
        try:
            severity = Severity(raw.get("severity"))
        except ValueError:
            raise ValueError("fixture event has an unsupported severity") from None
        events.append(Event(identity, str(event_type), severity, _parse_timestamp(raw.get("observed_at")), evidence))
    expected = document.get("expected")
    if not isinstance(expected, dict) or set(expected) - {"finding_rules", "chain_count", "max_elapsed_ms"}:
        raise ValueError("fixture expected results are missing or unsupported")
    rules = expected.get("finding_rules")
    chains = expected.get("chain_count")
    budget = expected.get("max_elapsed_ms", 1000)
    if not isinstance(rules, list) or len(set(rules)) != len(rules) or any(
        not isinstance(item, str) or not RULE_ID.fullmatch(item) for item in rules
    ):
        raise ValueError("expected finding_rules must be a string list")
    if type(chains) is not int or chains < 0 or type(budget) is not int or budget < 1 or budget > 60000:
        raise ValueError("expected chain count or performance budget is invalid")
    events = sorted(events, key=lambda item: (datetime.fromisoformat(item.observed_at), item.event_id))
    span = datetime.fromisoformat(events[-1].observed_at) - datetime.fromisoformat(events[0].observed_at)
    if span.total_seconds() > window_seconds:
        raise ValueError("fixture events exceed their production correlation window")
    return document, events


def _source_ids(finding: Finding) -> List[str]:
    values = finding.evidence.get("source_events")
    if isinstance(values, list):
        return [item for item in values if isinstance(item, str)]
    value = finding.evidence.get("source_event")
    return [value] if isinstance(value, str) else []


def _event_summary(event: Event) -> str:
    evidence = event.evidence
    if event.event_type == "process_started":
        return "Process started: %s" % evidence.get("executable", "unknown executable")
    if event.event_type == "connection_established":
        return "Connection established: %s" % evidence.get("endpoint", "unknown endpoint")
    if event.event_type.startswith("persistence_"):
        return "Persistence changed: %s" % evidence.get("path", "unknown entry")
    if event.event_type.startswith("loaded_image_"):
        return "Loaded code changed: %s" % evidence.get("path", "unknown image")
    return event.event_type.replace("_", " ").capitalize()


def build_chains(events: List[Event], findings: List[Finding]) -> List[Dict[str, object]]:
    """Build stable connected components from process identity and rule sources."""
    by_id = {event.event_id: event for event in events}
    parent = {event.event_id: event.event_id for event in events}

    def find(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(left: str, right: str) -> None:
        a, b = find(left), find(right)
        if a != b:
            parent[max(a, b)] = min(a, b)

    instances: Dict[str, List[str]] = {}
    for event in events:
        instance = event.evidence.get("process_instance")
        if isinstance(instance, str) and instance:
            instances.setdefault(instance, []).append(event.event_id)
    for identities in instances.values():
        for identity in identities[1:]:
            union(identities[0], identity)
    for finding in findings:
        identities = [item for item in _source_ids(finding) if item in parent]
        for identity in identities[1:]:
            union(identities[0], identity)

    components: Dict[str, Set[str]] = {}
    for identity in parent:
        components.setdefault(find(identity), set()).add(identity)
    chains = []
    for identities in components.values():
        related = [finding for finding in findings if set(_source_ids(finding)).intersection(identities)]
        if not related:
            continue
        ordered = sorted(
            (by_id[item] for item in identities),
            key=lambda item: (datetime.fromisoformat(item.observed_at), item.event_id),
        )
        rules = sorted({finding.rule_id for finding in related})
        digest = hashlib.sha256(("\n".join(item.event_id for item in ordered) + "\n" + "\n".join(rules)).encode()).hexdigest()[:20]
        techniques = []
        for rule in rules:
            if rule in ATTACK_RULES:
                technique_id, name = ATTACK_RULES[rule]
                techniques.append({"id": technique_id, "name": name, "rule_id": rule})
        persistence_paths = {
            item.evidence.get("path") for item in ordered
            if item.event_type.startswith("persistence_") and isinstance(item.evidence.get("path"), str)
        }
        if "RAT-CORR-003" in rules and any("/LaunchAgents/" in item for item in persistence_paths):
            techniques.append({"id": "T1543.001", "name": "Launch Agent", "rule_id": "RAT-CORR-003"})
        if "RAT-CORR-003" in rules and any("/LaunchDaemons/" in item for item in persistence_paths):
            techniques.append({"id": "T1543.004", "name": "Launch Daemon", "rule_id": "RAT-CORR-003"})
        chains.append({
            "chain_id": "chain-" + digest,
            "started_at": ordered[0].observed_at,
            "ended_at": ordered[-1].observed_at,
            "severity": max((finding.severity for finding in related), key=lambda value: list(Severity).index(value)).value,
            "rule_ids": rules,
            "techniques": techniques,
            "attack_mapping_notice": "Coverage context only; this mapping is not a verdict.",
            "nodes": [{
                "event_id": item.event_id,
                "event_type": item.event_type,
                "severity": item.severity.value,
                "observed_at": item.observed_at,
                "summary": _event_summary(item),
                "evidence": item.evidence,
            } for item in ordered],
        })
    return sorted(chains, key=lambda item: (item["started_at"], item["chain_id"]))


def _scrub_value(key: str, value: object) -> object:
    if isinstance(value, dict):
        return {child: _scrub_value(child, item) for child, item in value.items()}
    if isinstance(value, list):
        return [_scrub_value(key, item) for item in value]
    if not isinstance(value, str):
        return value
    lowered = key.lower()
    if lowered == "summary" and ":" in value:
        return value.split(":", 1)[0] + ": redacted evidence"
    if value.startswith(("/", "\\\\")) or re.match(r"^[A-Za-z]:[\\\\/]", value):
        return "path:" + hashlib.sha256(value.encode()).hexdigest()[:12]
    if "->" in value and ":" in value:
        return "endpoint:" + hashlib.sha256(value.encode()).hexdigest()[:12]
    if lowered in {"endpoint", "remote_endpoints"} or "address" in lowered:
        return "endpoint:" + hashlib.sha256(value.encode()).hexdigest()[:12]
    if lowered in {"path", "executable", "image", "images", "persistence", "examples", "notes"}:
        return "path:" + hashlib.sha256(value.encode()).hexdigest()[:12]
    if lowered == "process_instance":
        return "process:" + hashlib.sha256(value.encode()).hexdigest()[:12]
    return value


def investigation_bundle(fixture_id: str, chains: List[Dict[str, object]]) -> Dict[str, object]:
    return {
        "schema": 1,
        "fixture_id": fixture_id,
        "privacy": "paths, endpoints, and process-instance values are one-way tokenized",
        "chains": [_scrub_value("chains", item) for item in chains],
    }


def replay_fixture(path: Path) -> Dict[str, object]:
    document, events = load_fixture(path)
    started = time.perf_counter()
    current_ids = {event.event_id for event in events}
    observed_at = events[-1].observed_at
    findings, derived = correlate(events, current_ids, observed_at)
    native_findings, native_derived = correlate_native(events, current_ids, observed_at)
    findings += native_findings
    derived += native_derived
    chains = build_chains(events, findings)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    expected = document["expected"]
    actual_rules = sorted(finding.rule_id for finding in findings)
    expected_rules = sorted(expected["finding_rules"])
    budget = expected.get("max_elapsed_ms", 1000)
    assertions = [
        {"name": "finding_rules", "passed": actual_rules == expected_rules, "expected": expected_rules, "actual": actual_rules},
        {"name": "chain_count", "passed": len(chains) == expected["chain_count"], "expected": expected["chain_count"], "actual": len(chains)},
        {"name": "performance_budget", "passed": elapsed_ms <= budget, "expected_max_ms": budget, "actual_ms": elapsed_ms},
    ]
    passed = all(item["passed"] for item in assertions)
    return {
        "schema": 1,
        "status": "passed" if passed else "failed",
        "fixture": {
            "id": document["id"], "title": document["title"],
            "description": document["description"], "safety": document["safety"],
        },
        "summary": {
            "events": len(events), "findings": len(findings), "correlations": len(derived),
            "chains": len(chains), "elapsed_ms": elapsed_ms, "max_elapsed_ms": budget,
        },
        "assertions": assertions,
        "findings": [asdict(item) for item in findings],
        "chains": chains,
        "investigation_bundle": investigation_bundle(str(document["id"]), chains),
    }


def replay_suite(directory: Path) -> Dict[str, object]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("fixture suite path must be a non-symbolic-link directory")
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise ValueError("fixture suite contains no JSON fixtures")
    if len(paths) > MAX_FIXTURES:
        raise ValueError("fixture suite exceeds the %d fixture limit" % MAX_FIXTURES)
    results = [replay_fixture(path) for path in paths]
    passed = sum(result["status"] == "passed" for result in results)
    return {
        "schema": 1,
        "status": "passed" if passed == len(results) else "failed",
        "summary": {
            "fixtures": len(results), "passed": passed, "failed": len(results) - passed,
            "events": sum(result["summary"]["events"] for result in results),
            "findings": sum(result["summary"]["findings"] for result in results),
            "chains": sum(result["summary"]["chains"] for result in results),
        },
        "results": results,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rattler lab", description="Replay safe detection fixtures through production correlation logic.")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    commands = parser.add_subparsers(dest="command", required=True)
    replay = commands.add_parser("replay", help="replay one fixture")
    replay.add_argument("fixture", type=Path)
    bundle = commands.add_parser("bundle", help="emit only the privacy-scrubbed investigation bundle for one fixture")
    bundle.add_argument("fixture", type=Path)
    suite = commands.add_parser("suite", help="replay every JSON fixture in a directory")
    suite.add_argument("directory", type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        replayed = replay_fixture(args.fixture) if args.command in ("replay", "bundle") else None
        result = replayed["investigation_bundle"] if args.command == "bundle" else replayed if replayed is not None else replay_suite(args.directory)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(json.dumps({"schema": 1, "status": "invalid", "error": str(error), "detail": str(error)}, indent=2 if args.pretty else None), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if args.command == "bundle" or result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
