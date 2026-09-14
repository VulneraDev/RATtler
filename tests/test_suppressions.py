import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rattler.model import Event, Finding, Severity, Status
from rattler.suppressions import (
    add_exception,
    apply_exceptions,
    load_policy,
    remove_exception,
)


NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)


class SuppressionPolicyTests(unittest.TestCase):
    def test_refuses_path_only_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "CDHash, SHA-256"):
                add_exception(
                    Path(directory) / "exceptions.json",
                    "RAT-INJECT-005", {"path": "/tmp/plugin.dylib"}, "Expected test plugin",
                )

    def test_add_is_dry_run_until_explicitly_applied(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "exceptions.json"
            plan = add_exception(
                policy, "RAT-INJECT-005",
                {"path": "/tmp/plugin.dylib", "cdhash": "a" * 40},
                "Reviewed internal plugin", apply=False,
            )
            self.assertFalse(plan["applied"])
            self.assertFalse(policy.exists())
            applied = add_exception(
                policy, "RAT-INJECT-005",
                {"path": "/tmp/plugin.dylib", "cdhash": "a" * 40},
                "Reviewed internal plugin", apply=True,
            )
            self.assertTrue(applied["applied"])
            self.assertEqual(len(load_policy(policy)), 1)
            if os.name != "nt":
                self.assertEqual(os.stat(policy).st_mode & 0o777, 0o600)

    def test_exact_rule_path_and_cdhash_are_all_required(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "exceptions.json"
            result = add_exception(
                policy, "RAT-INJECT-005",
                {"path": "/tmp/plugin.dylib", "cdhash": "a" * 40},
                "Reviewed internal plugin", apply=True,
            )
            finding = Finding(
                "RAT-INJECT-005", "Identity changed", Severity.HIGH, "injection", "Changed",
                {"path": "/tmp/plugin.dylib", "cdhash": "a" * 40, "source_event": "event-1"},
            )
            event = Event(
                "event-1", "loaded_image_identity_changed", Severity.HIGH,
                NOW.isoformat(), {"path": "/tmp/plugin.dylib", "cdhash": "a" * 40},
            )
            check, findings, events = apply_exceptions(policy, [finding], [event], NOW)
            self.assertEqual(check.status, Status.HEALTHY)
            self.assertEqual(check.details["suppressed_findings"], 1)
            self.assertEqual(findings, [])
            self.assertEqual(events[0].severity, Severity.INFO)
            self.assertIn("reviewed_exception", events[0].evidence)
            self.assertEqual(load_policy(policy)[0]["id"], result["entry"]["id"])

            wrong_hash = Finding(
                "RAT-INJECT-005", "Identity changed", Severity.HIGH, "injection", "Changed",
                {"path": "/tmp/plugin.dylib", "cdhash": "b" * 40},
            )
            _check, retained, _events = apply_exceptions(policy, [wrong_hash], [], NOW)
            self.assertEqual(retained, [wrong_hash])

    def test_expired_exception_does_not_hide_a_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "exceptions.json"
            created = NOW - timedelta(days=2)
            document = {
                "schema": 1,
                "entries": [{
                    "id": "a" * 32,
                    "rule_id": "RAT-INJECT-005",
                    "match": {"path": "/tmp/plugin.dylib", "cdhash": "b" * 40},
                    "reason": "Temporary review",
                    "created_at": created.isoformat(),
                    "expires_at": (created + timedelta(days=1)).isoformat(),
                }],
            }
            policy.write_text(json.dumps(document), encoding="utf-8")
            if os.name != "nt":
                os.chmod(policy, 0o600)
            finding = Finding(
                "RAT-INJECT-005", "Identity changed", Severity.HIGH, "injection", "Changed",
                {"path": "/tmp/plugin.dylib", "cdhash": "b" * 40},
            )
            check, retained, _events = apply_exceptions(policy, [finding], [], NOW)
            self.assertEqual(retained, [finding])
            self.assertEqual(check.details["expired"], 1)

    def test_invalid_policy_fails_open_and_degrades_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "exceptions.json"
            policy.write_text("not json", encoding="utf-8")
            finding = Finding("RULE", "Finding", Severity.HIGH, "test", "test")
            check, retained, _events = apply_exceptions(policy, [finding], [], NOW)
            self.assertEqual(check.status, Status.UNKNOWN)
            self.assertEqual(retained, [finding])

    @unittest.skipIf(os.name == "nt", "POSIX permissions are not enforced on Windows")
    def test_broad_policy_permissions_fail_open(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "exceptions.json"
            added = add_exception(
                policy, "RAT-INJECT-005",
                {"path": "/tmp/plugin.dylib", "cdhash": "d" * 40},
                "Reviewed internal plugin", apply=True,
            )
            os.chmod(policy, 0o644)
            finding = Finding(
                "RAT-INJECT-005", "Identity changed", Severity.HIGH, "injection", "Changed",
                {"path": "/tmp/plugin.dylib", "cdhash": "d" * 40},
            )
            check, retained, _events = apply_exceptions(policy, [finding], [], NOW)
            self.assertEqual(check.status, Status.UNKNOWN)
            self.assertEqual(retained, [finding])
            self.assertEqual(added["entry"]["rule_id"], "RAT-INJECT-005")

    def test_remove_is_reviewed_before_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "exceptions.json"
            added = add_exception(
                policy, "RAT-INJECT-005",
                {"path": "/tmp/plugin.dylib", "sha256": "c" * 64},
                "Reviewed internal plugin", apply=True,
            )
            identifier = added["entry"]["id"]
            self.assertFalse(remove_exception(policy, identifier)["applied"])
            self.assertEqual(len(load_policy(policy)), 1)
            self.assertTrue(remove_exception(policy, identifier, apply=True)["applied"])
            self.assertEqual(load_policy(policy), [])


if __name__ == "__main__":
    unittest.main()
