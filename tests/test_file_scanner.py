import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rattler.file_scanner import discover_files, scan_target, static_findings
from rattler.model import Status
from rattler.suppressions import add_exception


class FakeRules:
    def match(self, data, timeout):
        if b"RATTLER_SAFE_FILE_CANARY_v1" not in data:
            return []
        return [SimpleNamespace(
            rule="RATtler_Safe_File_Canary",
            namespace="rattler_test",
            tags=["test"],
            meta={
                "description": "Harmless RATtler validation marker detected.",
                "severity": "info",
                "confidence": "test",
            },
        )]


class FileScannerTests(unittest.TestCase):
    def test_invalid_signature_in_staging_location_is_high_priority(self):
        record = {
            "path": "/tmp/tool",
            "sha256": "a" * 64,
            "size": 8192,
            "executable": True,
            "macho": True,
            "entropy": 4.0,
            "signature": "signed",
            "signature_valid": False,
            "cdhash": "b" * 40,
        }
        findings = static_findings(record)
        self.assertEqual([item.rule_id for item in findings], ["RAT-FILE-002"])
        self.assertEqual(findings[0].severity.value, "high")

    def test_bundled_yara_rules_compile_and_match_safe_marker_when_available(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            self.skipTest("optional yara-python is not installed")
        rules = Path(__file__).resolve().parents[1] / "rules"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "safe-marker.txt"
            target.write_text("RATTLER_SAFE_FILE_CANARY_v1", encoding="utf-8")
            result = scan_target(target, [rules])
        self.assertEqual(result["check"]["status"], Status.HEALTHY.value)
        self.assertEqual(result["summary"]["yara_rules"], 1)
        self.assertEqual(result["findings"][0]["evidence"]["confidence"], "test")

    def test_bundled_yara_rules_do_not_match_a_benign_script_when_available(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            self.skipTest("optional yara-python is not installed")
        rules = Path(__file__).resolve().parents[1] / "rules"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "hello.sh"
            target.write_text("#!/bin/sh\nprintf 'hello from a benign fixture\\n'\n", encoding="utf-8")
            result = scan_target(target, [rules])
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["findings"], [])

    @patch("rattler.file_scanner.compile_yara", return_value=(FakeRules(), None, [{"namespace": "rattler_test", "source": "test.yar", "sha256": "a" * 64}]))
    def test_hashes_and_matches_a_safe_yara_canary(self, _compile):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.txt"
            content = b"hello RATTLER_SAFE_FILE_CANARY_v1"
            target.write_bytes(content)
            result = scan_target(target, [Path(directory)])
        self.assertEqual(result["status"], "review")
        self.assertEqual(result["files"][0]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(result["findings"][0]["evidence"]["rule"], "RATtler_Safe_File_Canary")
        self.assertEqual(result["findings"][0]["severity"], "info")
        self.assertEqual(result["findings"][0]["evidence"]["rule_source_sha256"], "a" * 64)
        self.assertRegex(result["findings"][0]["rule_id"], r"^RAT-FILE-YARA-[0-9a-f]{24}$")

    @patch("rattler.file_scanner.compile_yara", return_value=(FakeRules(), None, [{"namespace": "rattler_test", "source": "test.yar", "sha256": "a" * 64}]))
    def test_identity_bound_exception_suppresses_repeat_file_match(self, _compile):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.txt"
            content = b"RATTLER_SAFE_FILE_CANARY_v1"
            target.write_bytes(content)
            policy = Path(directory) / "exceptions.json"
            first = scan_target(target, [Path(directory)])
            add_exception(
                policy, first["findings"][0]["rule_id"],
                {"path": str(target), "sha256": hashlib.sha256(content).hexdigest()},
                "Reviewed safe validation marker", apply=True,
            )
            result = scan_target(target, [Path(directory)], exception_policy=policy)
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["summary"]["suppressed_findings"], 1)

    @patch("rattler.file_scanner.compile_yara", return_value=(None, "no rules", []))
    def test_static_scan_flags_disguised_executable_without_yara(self, _compile):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "invoice.pdf.command"
            target.write_text("#!/bin/sh\necho harmless\n", encoding="utf-8")
            target.chmod(0o700)
            result = scan_target(target, [Path(directory)])
        self.assertEqual(result["status"], "risk")
        self.assertEqual(result["check"]["status"], Status.UNKNOWN.value)
        self.assertIn("RAT-FILE-001", {item["rule_id"] for item in result["findings"]})

    @patch("rattler.file_scanner.compile_yara", return_value=(None, None, []))
    def test_directory_scan_is_bounded_and_does_not_follow_symlinks(self, _compile):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(5):
                (root / ("file-%s.txt" % index)).write_text("safe", encoding="utf-8")
            if hasattr(os, "symlink"):
                try:
                    (root / "link.txt").symlink_to(root / "file-0.txt")
                except OSError:
                    pass
            files, details = discover_files(root, recursive=True, max_files=3)
            result = scan_target(root, max_files=3)
        self.assertEqual(len(files), 3)
        self.assertTrue(details["file_limit_reached"])
        self.assertEqual(result["summary"]["scanned_files"], 3)
        self.assertTrue(result["summary"]["limited"])

    def test_exact_file_limit_is_not_reported_as_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(3):
                (root / ("file-%s.txt" % index)).write_text("safe", encoding="utf-8")
            files, details = discover_files(root, recursive=True, max_files=3)
        self.assertEqual(len(files), 3)
        self.assertFalse(details["file_limit_reached"])

    @patch("rattler.file_scanner.MAX_DIRECTORIES", 2)
    def test_directory_traversal_stops_at_the_global_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a" / "nested").mkdir(parents=True)
            (root / "b").mkdir()
            files, details = discover_files(root, recursive=True, max_files=10)
        self.assertEqual(files, [])
        self.assertEqual(details["directories"], 2)
        self.assertTrue(details["directory_limit_reached"])

    def test_refuses_a_symbolic_link_target(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real.txt"
            target.write_text("safe", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symbolic links unavailable")
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                scan_target(link)

    @patch("rattler.file_scanner.compile_yara", return_value=(None, None, []))
    def test_total_byte_budget_stops_before_reading_next_file(self, _compile):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.bin").write_bytes(b"a" * 10)
            (root / "b.bin").write_bytes(b"b" * 10)
            result = scan_target(root, max_total_bytes=15)
        self.assertEqual(result["summary"]["scanned_files"], 1)
        self.assertTrue(result["summary"]["limited"])
        self.assertTrue(result["check"]["details"]["total_byte_limit_reached"])

    @patch("rattler.file_scanner.time.monotonic", side_effect=[0.0, 2.0])
    @patch("rattler.file_scanner.compile_yara", return_value=(None, None, []))
    def test_time_budget_stops_before_reading_a_file(self, _compile, _clock):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.bin"
            target.write_bytes(b"safe")
            result = scan_target(target, max_seconds=1)
        self.assertEqual(result["summary"]["scanned_files"], 0)
        self.assertTrue(result["summary"]["limited"])
        self.assertTrue(result["check"]["details"]["time_limit_reached"])

    @patch("rattler.file_scanner.compile_yara", return_value=(None, None, []))
    def test_oversized_file_does_not_consume_the_total_budget(self, _compile):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a-large.bin").write_bytes(b"a" * 20)
            (root / "b-small.bin").write_bytes(b"b" * 5)
            result = scan_target(root, max_file_bytes=10, max_total_bytes=10)
        self.assertEqual(result["summary"]["scanned_files"], 1)
        self.assertEqual(result["files"][0]["path"], str((root / "b-small.bin").resolve()))
        self.assertEqual(result["summary"]["bytes_read"], 5)


if __name__ == "__main__":
    unittest.main()
