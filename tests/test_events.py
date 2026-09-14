import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rattler.events import (
    _append_journal,
    _image_snapshot,
    _process_snapshot,
    correlate,
    diff_snapshots,
    parse_sockets,
    update_events,
)
from rattler.injection import LoadedImage, SignatureInfo
from rattler.model import Event, Severity, Status


NOW = "2026-09-14T01:00:00+00:00"


class SocketParsingTests(unittest.TestCase):
    def test_parses_listener_and_established_socket(self):
        output = (
            "p10\ncagent\nf3\nn*:4444\nTST=LISTEN\n"
            "f4\nn10.0.0.2:5000->203.0.113.5:443\nTST=ESTABLISHED\n"
        )
        sockets = parse_sockets(output)
        self.assertEqual([item.state for item in sockets], ["LISTEN", "ESTABLISHED"])
        self.assertEqual(sockets[1].pid, 10)


class EventDiffTests(unittest.TestCase):
    def test_emits_risky_process_and_connection_events(self):
        new = {
            "processes": {"10": {"ppid": 1, "executable": "/tmp/agent", "risk_reason": "temporary directory"}},
            "sockets": {"10|ESTABLISHED|local->remote": {
                "pid": 10, "process": "agent", "endpoint": "local->remote", "state": "ESTABLISHED"
            }},
            "persistence": {}, "images": {},
        }
        events = diff_snapshots({}, new, NOW)
        self.assertEqual([item.event_type for item in events], ["process_started", "connection_established"])
        self.assertEqual(events[0].severity, Severity.MEDIUM)

    def test_correlates_recent_process_with_new_connection(self):
        process = Event("p", "process_started", Severity.MEDIUM, NOW, {
            "pid": 10, "executable": "/tmp/agent", "risk_reason": "temporary directory"
        })
        connection = Event("c", "connection_established", Severity.INFO, NOW, {
            "pid": 10, "endpoint": "local->remote"
        })
        findings, derived = correlate([process, connection], {"c"}, NOW)
        self.assertEqual(findings[0].rule_id, "RAT-CORR-001")
        self.assertEqual(derived[0].severity, Severity.CRITICAL)

    def test_does_not_correlate_events_from_reused_pid(self):
        process = Event("p", "process_started", Severity.MEDIUM, NOW, {
            "pid": 10, "process_instance": "old-instance",
            "executable": "/tmp/agent", "risk_reason": "temporary directory",
        })
        connection = Event("c", "connection_established", Severity.INFO, NOW, {
            "pid": 10, "process_instance": "new-instance", "endpoint": "local->remote",
        })
        findings, derived = correlate([process, connection], {"c"}, NOW)
        self.assertEqual((findings, derived), ([], []))

    def test_cdhash_change_at_same_loaded_path_is_high_priority(self):
        old = {
            "processes": {}, "sockets": {}, "persistence": {},
            "images": {"42|/tmp/plugin.dylib": {
                "pid": 42, "process": "Test", "path": "/tmp/plugin.dylib",
                "cdhash": "a" * 40, "signature": "signed", "team_id": "TEAM123",
            }},
        }
        new = {
            "processes": {}, "sockets": {}, "persistence": {},
            "images": {"42|/tmp/plugin.dylib": {
                "pid": 42, "process": "Test", "path": "/tmp/plugin.dylib",
                "cdhash": "b" * 40, "signature": "signed", "team_id": "TEAM123",
            }},
        }
        events = diff_snapshots(old, new, NOW)
        findings, _derived = correlate(events, {events[0].event_id}, NOW)
        self.assertEqual(events[0].event_type, "loaded_image_identity_changed")
        self.assertEqual(events[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].rule_id, "RAT-INJECT-005")
        self.assertEqual(findings[0].evidence["previous_cdhash"], "a" * 40)

    def test_first_cdhash_enrichment_does_not_create_an_upgrade_alert(self):
        key = "42|/tmp/plugin.dylib"
        old = {"processes": {}, "sockets": {}, "persistence": {}, "images": {
            key: {"pid": 42, "process": "Test", "path": "/tmp/plugin.dylib"},
        }}
        new = {"processes": {}, "sockets": {}, "persistence": {}, "images": {
            key: {"pid": 42, "process": "Test", "path": "/tmp/plugin.dylib", "cdhash": "a" * 40,
                  "signature": "signed", "team_id": "TEAM123"},
        }}
        self.assertEqual(diff_snapshots(old, new, NOW), [])

    def test_cdhash_drift_survives_process_restart(self):
        old = {"processes": {}, "sockets": {}, "persistence": {}, "images": {
            "41|/tmp/plugin.dylib": {"pid": 41, "path": "/tmp/plugin.dylib", "cdhash": "a" * 40,
                                         "signature": "signed", "team_id": "TEAM123"},
        }}
        new = {"processes": {}, "sockets": {}, "persistence": {}, "images": {
            "99|/tmp/plugin.dylib": {"pid": 99, "path": "/tmp/plugin.dylib", "cdhash": "b" * 40,
                                         "signature": "signed", "team_id": "TEAM123"},
        }}
        events = diff_snapshots(old, new, NOW)
        self.assertEqual(events[0].event_type, "loaded_image_identity_changed")
        self.assertEqual(events[0].evidence["previous_pid"], 41)


class EventStateTests(unittest.TestCase):
    @patch("rattler.events.platform.system", return_value="Darwin")
    @patch("rattler.events.run")
    @patch("rattler.events.parse_loaded_images")
    @patch("rattler.events.is_macho", return_value=True)
    @patch("rattler.events.signature_metadata")
    def test_loaded_image_snapshot_persists_signing_identity(
        self, mocked_signature, _macho, mocked_images, mocked_run, _platform,
    ):
        path = "/tmp/plugin.dylib"
        mocked_run.return_value = SimpleNamespace(returncode=0, stdout="fixture")
        mocked_images.return_value = [LoadedImage(42, "Test", path)]
        mocked_signature.return_value = SignatureInfo(
            True, "signed", "TEAM123", "dev.example.plugin", "a" * 40,
        )
        snapshot = _image_snapshot()
        self.assertEqual(snapshot["42|/tmp/plugin.dylib"]["cdhash"], "a" * 40)
        self.assertEqual(snapshot["42|/tmp/plugin.dylib"]["team_id"], "TEAM123")

    @patch("rattler.events.run")
    def test_process_snapshot_excludes_engine_and_host_pid(self, mocked_run):
        mocked_run.return_value = SimpleNamespace(
            returncode=0,
            stdout=(
                f"{os.getpid()} 1 /tmp/rattler-engine\n"
                "424242 1 /tmp/RATtler.app/Contents/MacOS/RATtler\n"
                "525252 1 /tmp/review-me\n"
            ),
        )
        self.assertEqual(set(_process_snapshot({424242})), {"525252"})

    @patch("rattler.events.run")
    def test_process_snapshot_records_instance_and_ancestry(self, mocked_run):
        mocked_run.return_value = SimpleNamespace(
            returncode=0,
            stdout=(
                "1 0 Sun Sep 14 10:00:00 2026 /sbin/launchd\n"
                "10 1 Sun Sep 14 10:01:00 2026 /Applications/Parent.app/Parent\n"
                "20 10 Sun Sep 14 10:02:00 2026 /tmp/dropper\n"
            ),
        )
        snapshot = _process_snapshot()
        self.assertEqual([item["pid"] for item in snapshot["20"]["ancestry"]], [10, 1])
        self.assertEqual(len(snapshot["20"]["process_instance"]), 24)

    @patch("rattler.events.capture_snapshot")
    def test_first_run_initializes_private_state_without_event_flood(self, mocked_capture):
        mocked_capture.return_value = {"processes": {}, "sockets": {}, "persistence": {}, "images": {}}
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            check, events, findings = update_events(state)
            mode = os.stat(str(state)).st_mode & 0o777
            with state.open() as handle:
                document = json.load(handle)
        self.assertEqual(check.status, Status.HEALTHY)
        self.assertEqual((events, findings), ([], []))
        if os.name != "nt":
            self.assertEqual(mode, 0o600)
        self.assertEqual(document["schema"], 1)

    def test_journal_rotates_and_remains_private(self):
        event = Event("id", "process_started", Severity.INFO, NOW, {"pid": 10})
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "events.jsonl"
            _append_journal(journal, [event], 10)
            _append_journal(journal, [event], 10)
            mode = os.stat(str(journal)).st_mode & 0o777
            backup_exists = Path(str(journal) + ".1").exists()
        if os.name != "nt":
            self.assertEqual(mode, 0o600)
        self.assertTrue(backup_exists)


if __name__ == "__main__":
    unittest.main()
