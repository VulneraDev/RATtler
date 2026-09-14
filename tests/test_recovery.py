import json
import os
import tempfile
import unittest
from pathlib import Path

from rattler.recovery import backup, restore_all, status


class RecoveryVaultTests(unittest.TestCase):
    def test_backup_is_opt_in_and_content_addressed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Documents"
            root.mkdir()
            (root / "report.docx").write_bytes(b"clean report")
            (root / "program.bin").write_bytes(b"not eligible")
            store = base / "vault"
            plan = backup(store, [root])
            self.assertEqual(plan["planned_files"], 1)
            self.assertFalse((store / "manifest.json").exists())
            applied = backup(store, [root], apply=True)
            vault_status = status(store)
            with (store / "manifest.json").open(encoding="utf-8") as handle:
                manifest = json.load(handle)
            object_count = len(list((store / "objects").iterdir()))
        self.assertEqual(applied["stored_files"], 1)
        self.assertEqual(vault_status["recoverable_files"], 1)
        self.assertEqual(len(manifest["files"]), 1)
        self.assertEqual(object_count, 1)

    def test_restore_uses_previous_version_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Documents"
            root.mkdir()
            source = root / "report.docx"
            store = base / "vault"
            source.write_bytes(b"clean version one")
            backup(store, [root], apply=True)
            source.write_bytes(b"clean version two")
            backup(store, [root], apply=True)
            source.write_bytes(b"simulated encrypted payload")
            backup(store, [root], apply=True)
            destination = base / "Recovered"
            plan = restore_all(store, destination)
            applied = restore_all(store, destination, apply=True)
            recovered = destination / "Documents" / "report.docx"
            recovered_payload = recovered.read_bytes()
            recovered_mode = os.stat(str(recovered)).st_mode & 0o777
            with self.assertRaises(ValueError):
                restore_all(store, destination, apply=True)
        self.assertEqual(plan["planned_files"], 1)
        self.assertEqual(applied["restored_files"], 1)
        self.assertEqual(recovered_payload, b"clean version two")
        if os.name != "nt":
            self.assertEqual(recovered_mode, 0o600)

    def test_rotation_keeps_three_versions_and_prunes_old_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Documents"
            root.mkdir()
            source = root / "notes.txt"
            store = base / "vault"
            for generation in range(4):
                source.write_bytes(("version-%d" % generation).encode("ascii"))
                backup(store, [root], apply=True)
            with (store / "manifest.json").open(encoding="utf-8") as handle:
                manifest = json.load(handle)
            versions = manifest["files"][str(source)]["versions"]
            objects = list((store / "objects").iterdir())
        self.assertEqual(len(versions), 3)
        self.assertEqual(len(objects), 3)

    def test_quota_and_file_size_limits_skip_content(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Pictures"
            root.mkdir()
            (root / "large.jpg").write_bytes(b"x" * 100)
            store = base / "vault"
            result = backup(store, [root], quota_bytes=50, max_file_bytes=200, apply=True)
        self.assertEqual(result["stored_files"], 0)
        self.assertEqual(result["skipped_files"], 1)

    def test_corrupted_object_is_not_recovered(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Documents"
            root.mkdir()
            (root / "report.pdf").write_bytes(b"verified")
            store = base / "vault"
            backup(store, [root], apply=True)
            object_path = next((store / "objects").iterdir())
            object_path.write_bytes(b"tampered")
            result = restore_all(store, base / "Recovered", apply=True)
        self.assertEqual(result["restored_files"], 0)
        self.assertEqual(result["skipped_files"], 1)

    @unittest.skipIf(os.name == "nt", "symbolic-link behavior differs on Windows")
    def test_symbolic_link_store_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Documents"
            root.mkdir()
            store = base / "vault"
            store.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                backup(store, [root], apply=True)


if __name__ == "__main__":
    unittest.main()
