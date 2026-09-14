import json
import os
import tempfile
import unittest
from pathlib import Path

from rattler.model import Severity, Status
from rattler.ransomware import CANARY_NAME, scan_ransomware


class RansomwareSensorTests(unittest.TestCase):
    def test_first_scan_initializes_private_state_and_canary(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Documents"
            root.mkdir()
            (root / "notes.txt").write_text("safe", encoding="utf-8")
            state = base / "state" / "ransomware.json"
            check, findings, events = scan_ransomware(state, [root])
            with state.open(encoding="utf-8") as handle:
                document = json.load(handle)
            canary = state.with_name(CANARY_NAME)
            state_mode = os.stat(str(state)).st_mode & 0o777
            canary_mode = os.stat(str(canary)).st_mode & 0o777
        self.assertEqual(check.status, Status.HEALTHY)
        self.assertFalse(check.details["initialized"])
        self.assertEqual(check.details["monitored_files"], 1)
        self.assertEqual((findings, events), ([], []))
        self.assertEqual(document["schema"], 1)
        if os.name != "nt":
            self.assertEqual((state_mode, canary_mode), (0o600, 0o600))

    def test_encryption_extension_replacements_are_high_priority(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Documents"
            root.mkdir()
            state = base / "state" / "ransomware.json"
            for index in range(3):
                (root / ("file%d.txt" % index)).write_text("safe", encoding="utf-8")
            scan_ransomware(state, [root])
            for index in range(3):
                original = root / ("file%d.txt" % index)
                original.rename(Path(str(original) + ".locked"))
            check, findings, events = scan_ransomware(state, [root])
        self.assertEqual(check.status, Status.HEALTHY)
        self.assertIn("RAT-RANSOM-002", [item.rule_id for item in findings])
        self.assertTrue(any(item.severity == Severity.HIGH for item in findings))
        self.assertIn("ransomware_extension_burst", [item.event_type for item in events])

    def test_ransom_note_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Desktop"
            root.mkdir()
            state = base / "state" / "ransomware.json"
            scan_ransomware(state, [root])
            (root / "README_TO_DECRYPT.txt").write_text("test fixture", encoding="utf-8")
            _, findings, _ = scan_ransomware(state, [root])
        self.assertIn("RAT-RANSOM-004", [item.rule_id for item in findings])

    def test_bulk_rewrites_are_detected_without_reading_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Pictures"
            root.mkdir()
            state = base / "state" / "ransomware.json"
            for index in range(45):
                (root / ("photo%d.jpg" % index)).write_bytes(b"safe")
            scan_ransomware(state, [root])
            for index in range(45):
                (root / ("photo%d.jpg" % index)).write_bytes(b"changed payload")
            _, findings, _ = scan_ransomware(state, [root])
        self.assertIn("RAT-RANSOM-003", [item.rule_id for item in findings])

    def test_canary_damage_is_critical_and_not_auto_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Documents"
            root.mkdir()
            state = base / "state" / "ransomware.json"
            scan_ransomware(state, [root])
            canary = state.with_name(CANARY_NAME)
            canary.write_text("changed", encoding="utf-8")
            _, findings, events = scan_ransomware(state, [root])
        finding = next(item for item in findings if item.rule_id == "RAT-RANSOM-001")
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(events[0].event_type, "ransomware_canary_changed")

    def test_file_limit_is_distributed_across_protected_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            roots = [base / name for name in ("Desktop", "Documents", "Pictures")]
            for root in roots:
                root.mkdir()
                for index in range(50):
                    (root / ("file-%03d.txt" % index)).write_text("safe", encoding="utf-8")
            state = base / "state" / "ransomware.json"
            check, _, _ = scan_ransomware(state, roots, max_files=30)
            with state.open(encoding="utf-8") as handle:
                paths = json.load(handle)["files"]
        self.assertEqual(check.details["monitored_files"], 30)
        for root in roots:
            self.assertTrue(any(path.startswith(str(root)) for path in paths))


if __name__ == "__main__":
    unittest.main()
