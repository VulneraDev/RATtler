import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from rattler.file_events import native_file_event_sensor
from rattler.model import Status


class NativeFileEventTests(unittest.TestCase):
    def _state(self, directory: str, **overrides: object) -> Path:
        document = {
            "schema": 1,
            "pid": os.getpid(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "stream_active": True,
            "roots_watched": 3,
            "latency_seconds": 1.0,
            "events_seen": 12,
            "triggered_scans": 2,
            "dropped_events_total": 0,
            "unreconciled_drop": False,
            "last_event_id": 44,
            "last_event_at": datetime.now(timezone.utc).isoformat(),
            "path_data_retained": False,
        }
        document.update(overrides)
        path = Path(directory) / "fsevents-state.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        if os.name != "nt":
            path.chmod(0o600)
        return path

    def test_live_private_stream_is_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            check = native_file_event_sensor(self._state(directory))
        self.assertEqual(check.status, Status.HEALTHY)
        self.assertFalse(check.details["path_data_retained"])

    def test_unreconciled_drop_reduces_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            check = native_file_event_sensor(self._state(
                directory, unreconciled_drop=True, dropped_events_total=3,
            ))
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertIn("reconciliation", check.message)

    def test_inactive_stream_is_unhealthy(self):
        with tempfile.TemporaryDirectory() as directory:
            check = native_file_event_sensor(self._state(directory, stream_active=False))
        self.assertEqual(check.status, Status.UNHEALTHY)

    def test_missing_protected_root_is_degraded(self):
        with tempfile.TemporaryDirectory() as directory:
            check = native_file_event_sensor(self._state(directory, roots_watched=2))
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertIn("roots", check.message)

    @patch("rattler.file_events._process_alive", return_value=False)
    def test_stopped_host_is_unhealthy(self, _mocked_alive):
        with tempfile.TemporaryDirectory() as directory:
            check = native_file_event_sensor(self._state(directory))
        self.assertEqual(check.status, Status.UNHEALTHY)

    def test_stale_heartbeat_is_degraded(self):
        stale = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        with tempfile.TemporaryDirectory() as directory:
            check = native_file_event_sensor(self._state(directory, updated_at=stale))
        self.assertEqual(check.status, Status.DEGRADED)

    def test_broad_permissions_are_not_trusted(self):
        if os.name == "nt":
            self.skipTest("POSIX permissions are not available")
        with tempfile.TemporaryDirectory() as directory:
            path = self._state(directory)
            path.chmod(0o644)
            check = native_file_event_sensor(path)
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertIn("permissions", check.message)

    def test_path_bearing_state_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            check = native_file_event_sensor(self._state(
                directory, paths=["/Users/demo/Documents/private.txt"],
            ))
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertIn("schema", check.message)


if __name__ == "__main__":
    unittest.main()
