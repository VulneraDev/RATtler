import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rattler.assessment import build_assessment
from rattler.behavior import (
    ProcessInfo,
    _parse_lsof,
    inspect_launchd_file,
    parse_processes,
    suspicious_location,
)
from rattler.model import BehaviorReport, Check, Finding, Severity, Status
from rattler.providers import Provider


class FakeProvider(Provider):
    name = "fake"

    def checks(self):
        return [Check("av", Status.HEALTHY, "enabled")]


class ProcessSensorTests(unittest.TestCase):
    def test_parses_process_inventory(self):
        result = parse_processes("  10 1 /usr/bin/safe\n20 10 /tmp/dropper\ninvalid")
        self.assertEqual(result[1], ProcessInfo(20, 10, "/tmp/dropper"))

    def test_detects_risky_location(self):
        self.assertEqual(suspicious_location("/tmp/dropper", "/Users/test"), "temporary directory")
        self.assertEqual(
            suspicious_location("/Users/test/Downloads/tool", "/Users/test"),
            "Downloads directory",
        )
        self.assertIsNone(suspicious_location("/Applications/Safari.app/Safari", "/Users/test"))

    def test_parses_lsof_machine_output(self):
        output = "p123\ncserver\nn*:4444\np456\nclocal\nn127.0.0.1:8000\n"
        self.assertEqual(_parse_lsof(output), [(123, "server", "*:4444"), (456, "local", "127.0.0.1:8000")])

    def test_deduplicates_lsof_records(self):
        output = "p123\ncserver\nn*:4444\nn*:4444\n"
        self.assertEqual(_parse_lsof(output), [(123, "server", "*:4444")])


class PersistenceTests(unittest.TestCase):
    def test_detects_preload_injection_and_temp_program(self):
        with tempfile.TemporaryDirectory() as directory:
            plist = Path(directory) / "evil.plist"
            with plist.open("wb") as handle:
                plistlib.dump({
                    "Label": "test.evil",
                    "ProgramArguments": ["/tmp/helper"],
                    "EnvironmentVariables": {"DYLD_INSERT_LIBRARIES": "/tmp/inject.dylib"},
                }, handle)
            findings = inspect_launchd_file(plist, "/Users/test")
        self.assertEqual({finding.rule_id for finding in findings}, {
            "RAT-INJECT-001", "RAT-PERSIST-005", "RAT-PERSIST-007"
        })


class AssessmentTests(unittest.TestCase):
    @patch("rattler.providers.socket.gethostname", return_value="test-host")
    @patch("rattler.providers.platform.platform", return_value="test-platform")
    def test_high_finding_makes_assessment_unhealthy(self, _platform, _hostname):
        behavior = BehaviorReport(
            sensors=[Check("processes", Status.HEALTHY, "ok")],
            findings=[Finding("RULE", "Suspicious", Severity.HIGH, "process", "reason")],
        )
        self.assertEqual(build_assessment(FakeProvider(), behavior).status, Status.UNHEALTHY)


if __name__ == "__main__":
    unittest.main()
