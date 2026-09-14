import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from rattler.model import Status
from rattler.operation import continuous_operation_sensor


class ContinuousOperationTests(unittest.TestCase):
    def _state(self, directory: str, *, status: str = "active", age: int = 0) -> Path:
        now = datetime.now(timezone.utc)
        path = Path(directory) / "operation-state.json"
        path.write_text(json.dumps({
            "schema": 1, "status": status, "pid": os.getpid(), "interval_seconds": 60,
            "updated_at": (now - timedelta(seconds=age)).isoformat(),
            "last_scan_at": now.isoformat(), "menu_bar": True, "launch_at_login": False,
        }))
        if os.name != "nt":
            path.chmod(0o600)
        return path

    def test_active_private_heartbeat_is_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            check = continuous_operation_sensor(self._state(directory))
        self.assertEqual(check.status, Status.HEALTHY)
        self.assertTrue(check.details["host_process_alive"])

    def test_explicit_pause_reduces_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            check = continuous_operation_sensor(self._state(directory, status="paused"))
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertIn("explicitly paused", check.message)

    def test_stale_heartbeat_is_degraded(self):
        with tempfile.TemporaryDirectory() as directory:
            check = continuous_operation_sensor(self._state(directory, age=600))
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertIn("stale", check.message)

    @patch("rattler.operation._process_alive", return_value=False)
    def test_stopped_host_is_unhealthy(self, _mocked_alive):
        with tempfile.TemporaryDirectory() as directory:
            check = continuous_operation_sensor(self._state(directory))
        self.assertEqual(check.status, Status.UNHEALTHY)

    def test_broad_permissions_are_not_trusted(self):
        if os.name == "nt":
            self.skipTest("POSIX permissions are not available")
        with tempfile.TemporaryDirectory() as directory:
            path = self._state(directory)
            path.chmod(0o644)
            check = continuous_operation_sensor(path)
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertIn("permissions", check.message)

    def test_symbolic_link_is_refused(self):
        if os.name == "nt":
            self.skipTest("symbolic link behavior differs on Windows")
        with tempfile.TemporaryDirectory() as directory:
            target = self._state(directory)
            link = Path(directory) / "operation-link.json"
            link.symlink_to(target)
            check = continuous_operation_sensor(link)
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertIn("safe regular file", check.message)


if __name__ == "__main__":
    unittest.main()
