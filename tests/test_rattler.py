import json
import unittest
from unittest.mock import patch

from rattler.model import Check, Status
from rattler.providers import MacOSProvider, WindowsDefenderProvider, _overall, select_provider
from rattler.runner import CommandResult


class OverallStatusTests(unittest.TestCase):
    def test_unhealthy_wins(self):
        checks = [Check("a", Status.HEALTHY, "ok"), Check("b", Status.UNHEALTHY, "bad")]
        self.assertEqual(_overall(checks), Status.UNHEALTHY)

    def test_all_healthy(self):
        self.assertEqual(_overall([Check("a", Status.HEALTHY, "ok")]), Status.HEALTHY)


class ProviderTests(unittest.TestCase):
    def test_provider_selection(self):
        self.assertEqual(select_provider("Darwin").name, "macos-built-in")
        self.assertEqual(select_provider("Windows").name, "microsoft-defender")
        self.assertEqual(select_provider("Linux").name, "clamav")

    @patch("rattler.providers.run")
    def test_gatekeeper_disabled_is_unhealthy(self, mocked_run):
        mocked_run.return_value = CommandResult(1, "", "assessments disabled")
        self.assertEqual(MacOSProvider()._gatekeeper().status, Status.UNHEALTHY)

    @patch("rattler.providers.run")
    def test_defender_status(self, mocked_run):
        payload = json.dumps({
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "AntivirusSignatureVersion": "1.2.3",
            "AntivirusSignatureLastUpdated": "today",
        })
        mocked_run.return_value = CommandResult(0, payload, "")
        checks = WindowsDefenderProvider().checks()
        self.assertTrue(all(check.status == Status.HEALTHY for check in checks))


if __name__ == "__main__":
    unittest.main()
