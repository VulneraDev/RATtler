import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from rattler.model import Severity, Status
from rattler.native_bridge import (
    correlate_native,
    ingest_native_events,
    translate_native_event,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "native/macos/fixtures/injection-chain.jsonl"


def native_event(event_type, **extra):
    event = {
        "schema": 1,
        "sensor": "rattler-es",
        "timestamp_ns": 1789347600000000000,
        "event_type": event_type,
        "pid": 10,
        "path": "/Applications/Test.app/Contents/MacOS/Test",
        "dropped_since_previous": 0,
    }
    event.update(extra)
    return event


class NativeTranslationTests(unittest.TestCase):
    def test_writable_executable_memory_is_high(self):
        event, findings = translate_native_event(
            native_event("mprotect", protection=6, address=4096, size=4096), "id"
        )
        self.assertEqual(event.severity, Severity.HIGH)
        self.assertEqual(findings[0].rule_id, "RAT-NATIVE-002")

    def test_signature_invalidation_is_critical(self):
        event, findings = translate_native_event(native_event("cs_invalidated"), "id")
        self.assertEqual(event.severity, Severity.CRITICAL)
        self.assertEqual(findings[0].rule_id, "RAT-NATIVE-001")

    def test_sequence_gap_becomes_coverage_finding(self):
        _event, findings = translate_native_event(
            native_event("exec", dropped_since_previous=4, global_sequence=12), "id"
        )
        self.assertEqual(findings[0].rule_id, "RAT-NATIVE-000")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_task_port_and_remote_thread_correlate(self):
        raw = [json.loads(line) for line in FIXTURE.read_text().splitlines()]
        events = [translate_native_event(item, str(index))[0] for index, item in enumerate(raw)]
        findings, derived = correlate_native(events, {events[-1].event_id}, events[-1].observed_at)
        self.assertEqual(findings[0].rule_id, "RAT-NATIVE-006")
        self.assertEqual(derived[0].severity, Severity.CRITICAL)

    def test_ransomware_guard_shadow_and_enforcement_decisions(self):
        shadow_event, shadow_findings = translate_native_event(
            native_event("ransomware_guard", would_block=True, blocked=False, reason="rapid_file_mutations"),
            "shadow",
        )
        blocked_event, blocked_findings = translate_native_event(
            native_event("ransomware_guard", would_block=True, blocked=True, reason="canary_write"),
            "blocked",
        )
        self.assertEqual(shadow_event.severity, Severity.HIGH)
        self.assertEqual(shadow_findings[0].rule_id, "RAT-RANSOM-100")
        self.assertEqual(blocked_event.severity, Severity.CRITICAL)
        self.assertEqual(blocked_findings[0].rule_id, "RAT-RANSOM-101")


class NativeCursorTests(unittest.TestCase):
    def test_initializes_at_end_then_ingests_appended_events(self):
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "native.jsonl"
            cursor_path = Path(directory) / "cursor.json"
            event_path.write_bytes(b"")
            first, events, findings = ingest_native_events(event_path, cursor_path)
            with event_path.open("ab") as handle:
                handle.write(FIXTURE.read_bytes())
            second, events, findings = ingest_native_events(event_path, cursor_path)
            cursor_mode = os.stat(str(cursor_path)).st_mode & 0o777
        self.assertEqual(first.status, Status.HEALTHY)
        self.assertEqual(first.message, "native event cursor initialized")
        self.assertEqual(second.status, Status.HEALTHY)
        self.assertEqual(len(events), 3)
        self.assertEqual({item.rule_id for item in findings}, {"RAT-NATIVE-004", "RAT-NATIVE-006"})
        if os.name != "nt":
            self.assertEqual(cursor_mode, 0o600)

    def test_malformed_event_is_skipped_and_degrades_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "native.jsonl"
            cursor_path = Path(directory) / "cursor.json"
            event_path.write_bytes(b"")
            ingest_native_events(event_path, cursor_path)
            with event_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(native_event("exec", timestamp_ns=10 ** 30)) + "\n")
            check, events, findings = ingest_native_events(event_path, cursor_path)
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertEqual(check.details["malformed"], 1)
        self.assertEqual(events, [])
        self.assertEqual(findings, [])

    def test_heartbeat_is_consumed_without_activity_noise(self):
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "native.jsonl"
            cursor_path = Path(directory) / "cursor.json"
            event_path.write_bytes(b"")
            ingest_native_events(event_path, cursor_path)
            heartbeat = native_event("heartbeat", timestamp_ns=time.time_ns())
            with event_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(heartbeat) + "\n")
            check, events, findings = ingest_native_events(event_path, cursor_path)
        self.assertEqual(check.status, Status.HEALTHY)
        self.assertEqual(check.details["heartbeats"], 1)
        self.assertEqual(events, [])
        self.assertEqual(findings, [])

    def test_stale_native_stream_degrades_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "native.jsonl"
            cursor_path = Path(directory) / "cursor.json"
            event_path.write_bytes(b"")
            stale = time.time() - 60
            os.utime(str(event_path), (stale, stale))
            check, _events, _findings = ingest_native_events(event_path, cursor_path)
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertEqual(check.message, "native sensor heartbeat is stale")

    def test_native_collector_emits_periodic_heartbeat(self):
        source = (ROOT / "native/macos/Sources/rattler_es_sensor.c").read_text(encoding="utf-8")
        self.assertIn("emit_heartbeat", source)
        self.assertIn("15 * NSEC_PER_SEC", source)
        self.assertIn('json_cdhash(output, process->cdhash)', source)

    def test_native_guard_defaults_to_shadow_and_requires_enforcement_acknowledgement(self):
        source = (ROOT / "native/macos/Sources/rattler_es_guard.c").read_text(encoding="utf-8")
        self.assertIn("g_mode = GUARD_SHADOW", source)
        self.assertIn("--acknowledge-enforcement", source)
        self.assertIn("ES_EVENT_TYPE_AUTH_OPEN", source)
        self.assertIn("es_respond_flags_result", source)


if __name__ == "__main__":
    unittest.main()
