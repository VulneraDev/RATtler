import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rattler.events import (
    _append_journal,
    _process_snapshot,
    correlate,
    diff_snapshots,
    parse_sockets,
    update_events,
)
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


class EventStateTests(unittest.TestCase):
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
