import json
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from rattler.detection_lab import build_chains, load_fixture, main, replay_fixture, replay_suite
from rattler.model import Event, Finding, Severity


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "detections/fixtures"
NOW = "2026-09-14T12:00:00+00:00"


class DetectionLabTests(unittest.TestCase):
    def test_community_fixture_suite_passes(self):
        result = replay_suite(FIXTURES)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["summary"]["fixtures"], 2)
        self.assertEqual(result["summary"]["failed"], 0)

    def test_positive_fixture_uses_production_correlation_and_chainlight(self):
        result = replay_fixture(FIXTURES / "staged-network-persistence.json")
        self.assertEqual([item["rule_id"] for item in result["findings"]], ["RAT-CORR-001", "RAT-CORR-003"])
        self.assertEqual(result["chains"][0]["chain_id"], "chain-bb44fa3069aeed1218e5")
        self.assertEqual([item["event_type"] for item in result["chains"][0]["nodes"]], [
            "process_started", "connection_established", "persistence_added",
        ])
        self.assertEqual(result["chains"][0]["techniques"][0]["id"], "T1543.001")
        self.assertIn("not a verdict", result["chains"][0]["attack_mapping_notice"])

    def test_negative_fixture_asserts_no_alert(self):
        result = replay_fixture(FIXTURES / "routine-signed-activity.json")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["chains"], [])

    def test_chainlight_never_joins_reused_pid_without_matching_instance(self):
        old = Event("old", "process_started", Severity.MEDIUM, NOW, {
            "pid": 42, "process_instance": "old-instance", "executable": "/tmp/old",
        })
        new = Event("new", "connection_established", Severity.INFO, NOW, {
            "pid": 42, "process_instance": "new-instance", "endpoint": "local->remote",
        })
        finding = Finding("TEST-001", "test", Severity.HIGH, "test", "test", {"source_events": ["old"]})
        chains = build_chains([old, new], [finding])
        self.assertEqual([node["event_id"] for node in chains[0]["nodes"]], ["old"])

    def test_investigation_bundle_tokenizes_private_values_and_summaries(self):
        result = replay_fixture(FIXTURES / "staged-network-persistence.json")
        encoded = json.dumps(result["investigation_bundle"])
        self.assertNotIn("/tmp/rattler-fixture-agent", encoded)
        self.assertNotIn("127.0.0.1:49152", encoded)
        self.assertNotIn("synthetic-process-a", encoded)
        self.assertIn("path:", encoded)
        self.assertIn("endpoint:", encoded)

    def test_fixture_rejects_payload_content_and_symlinks(self):
        source = json.loads((FIXTURES / "routine-signed-activity.json").read_text())
        source["events"][0]["evidence"]["payload"] = "harmless but forbidden"
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture.json"
            fixture.write_text(json.dumps(source))
            with self.assertRaisesRegex(ValueError, "payload content"):
                load_fixture(fixture)
            link = Path(directory) / "link.json"
            link.symlink_to(fixture)
            with self.assertRaisesRegex(ValueError, "non-symbolic-link"):
                load_fixture(link)

    def test_fixture_requires_process_instance_and_timezone(self):
        source = json.loads((FIXTURES / "routine-signed-activity.json").read_text())
        del source["events"][0]["evidence"]["process_instance"]
        source["events"][1]["observed_at"] = "2026-09-14T12:10:01"
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture.json"
            fixture.write_text(json.dumps(source))
            with self.assertRaisesRegex(ValueError, "process_instance"):
                load_fixture(fixture)

    def test_fixture_rejects_duplicate_keys_and_non_finite_numbers(self):
        fixture_text = (FIXTURES / "routine-signed-activity.json").read_text()
        duplicate = fixture_text.replace('"schema": 1,', '"schema": 1, "schema": 1,', 1)
        non_finite = fixture_text.replace('"pid": 7331', '"pid": 7331, "score": NaN', 1)
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture.json"
            fixture.write_text(duplicate)
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_fixture(fixture)
            fixture.write_text(non_finite)
            with self.assertRaisesRegex(ValueError, "non-finite number"):
                load_fixture(fixture)

    def test_cli_reports_assertion_failure_separately_from_invalid_input(self):
        source = json.loads((FIXTURES / "routine-signed-activity.json").read_text())
        source["expected"]["chain_count"] = 1
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture.json"
            fixture.write_text(json.dumps(source))
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["replay", str(fixture)]), 1)
                self.assertEqual(main(["replay", str(Path(directory) / "missing.json")]), 2)


if __name__ == "__main__":
    unittest.main()
