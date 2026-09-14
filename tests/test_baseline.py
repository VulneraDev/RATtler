import os
import tempfile
import unittest
from pathlib import Path

from rattler.baseline import (
    Asset,
    Fingerprint,
    _load,
    capture,
    compare_entries,
    create_baseline,
    check_baseline,
    write_baseline,
)
from rattler.model import Severity


class FingerprintTests(unittest.TestCase):
    def test_fingerprints_content_and_security_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.plist"
            path.write_bytes(b"known-good")
            entries, skipped = capture([Asset(str(path), "launchd_plist")])
        self.assertEqual(skipped, 0)
        self.assertEqual(entries[0].sha256, "edb89d09b913b577efbd63f53446d060c97d339166531661a5196a0cf6b796bd")

    def test_baseline_is_written_private_and_loads(self):
        entry = Fingerprint("/tmp/example", "loaded_macho", "abc", 1, 0o755, 501, 20)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            summary = write_baseline(path, [entry])
            mode = os.stat(str(path)).st_mode & 0o777
            loaded = _load(path)
        if os.name != "nt":
            self.assertEqual(mode, 0o600)
        self.assertEqual(loaded, [entry])
        self.assertEqual(summary["entries"], 1)


class ComparisonTests(unittest.TestCase):
    def test_changed_startup_executable_is_critical(self):
        old = Fingerprint("/opt/helper", "startup_executable", "old", 10, 0o755, 0, 0)
        new = Fingerprint("/opt/helper", "startup_executable", "new", 10, 0o755, 0, 0)
        findings = compare_entries([old], [new])
        self.assertEqual(findings[0].rule_id, "RAT-BASE-002")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("sha256", findings[0].evidence["changed"])

    def test_new_launchd_entry_is_high(self):
        new = Fingerprint("/Library/LaunchAgents/new.plist", "launchd_plist", "hash", 10, 0o644, 0, 0)
        findings = compare_entries([], [new])
        self.assertEqual(findings[0].rule_id, "RAT-BASE-003")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_create_then_check_detects_plist_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "LaunchAgents"
            root.mkdir()
            plist = root / "test.agent.plist"
            plist.write_bytes(b"<?xml version='1.0'?><plist><dict><key>Label</key><string>good</string></dict></plist>")
            baseline = Path(directory) / "baseline.json"
            create_baseline(baseline, launchd_roots=[root], include_loaded_code=False)
            plist.write_bytes(b"<?xml version='1.0'?><plist><dict><key>Label</key><string>changed</string></dict></plist>")
            check, findings = check_baseline(
                baseline, launchd_roots=[root], include_loaded_code=False
            )
        self.assertEqual(check.status.value, "healthy")
        self.assertEqual(findings[0].rule_id, "RAT-BASE-002")


if __name__ == "__main__":
    unittest.main()
