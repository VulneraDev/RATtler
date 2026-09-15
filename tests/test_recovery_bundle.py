import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rattler.recovery import backup
from rattler.recovery_bundle import MAGIC, export_bundle, restore_bundle


class EncryptedRecoveryBundleTests(unittest.TestCase):
    def _vault(self, base: Path):
        root = base / "Documents"
        root.mkdir()
        source = root / "report.docx"
        store = base / "vault"
        source.write_bytes(b"clean version one")
        backup(store, [root], apply=True)
        source.write_bytes(b"clean version two")
        backup(store, [root], apply=True)
        return source, store

    def _fast_kdf(self):
        return patch.multiple(
            "rattler.recovery_bundle", ARGON2_MEMORY_KIB=8 * 1024, ARGON2_ITERATIONS=1,
        )

    def test_encrypted_bundle_round_trip_recovers_previous_version(self):
        with tempfile.TemporaryDirectory() as directory, self._fast_kdf():
            base = Path(directory)
            source, store = self._vault(base)
            bundle = base / "USB" / "RATtler-Recovery.rattlervault"
            bundle.parent.mkdir()
            plan = export_bundle(store, bundle)
            exported = export_bundle(store, bundle, "correct horse battery", apply=True)
            encrypted = bundle.read_bytes()
            destination = base / "Recovered"
            restored = restore_bundle(
                bundle, destination, "correct horse battery", apply=True,
            )
            recovered = destination / "Documents" / source.name
            payload = recovered.read_bytes()
        self.assertFalse(plan["applied"])
        self.assertTrue(exported["encrypted"])
        self.assertEqual(encrypted[:len(MAGIC)], MAGIC)
        self.assertNotIn(b"clean version one", encrypted)
        self.assertNotIn(str(source).encode("utf-8"), encrypted)
        self.assertEqual(restored["restored_files"], 1)
        self.assertEqual(payload, b"clean version one")

    def test_wrong_password_does_not_create_recovery_folder(self):
        with tempfile.TemporaryDirectory() as directory, self._fast_kdf():
            base = Path(directory)
            _, store = self._vault(base)
            bundle = base / "copy.rattlervault"
            export_bundle(store, bundle, "correct horse battery", apply=True)
            destination = base / "Recovered"
            with self.assertRaisesRegex(ValueError, "incorrect or the bundle is damaged"):
                restore_bundle(bundle, destination, "wrong password")
        self.assertFalse(destination.exists())

    def test_tampered_bundle_is_rejected_before_recovery(self):
        with tempfile.TemporaryDirectory() as directory, self._fast_kdf():
            base = Path(directory)
            _, store = self._vault(base)
            bundle = base / "copy.rattlervault"
            export_bundle(store, bundle, "correct horse battery", apply=True)
            payload = bytearray(bundle.read_bytes())
            payload[-30] ^= 0x40
            bundle.write_bytes(payload)
            destination = base / "Recovered"
            with self.assertRaisesRegex(ValueError, "incorrect or the bundle is damaged"):
                restore_bundle(bundle, destination, "correct horse battery", apply=True)
        self.assertFalse(destination.exists())

    def test_short_password_and_existing_destination_are_refused(self):
        with tempfile.TemporaryDirectory() as directory, self._fast_kdf():
            base = Path(directory)
            _, store = self._vault(base)
            bundle = base / "copy.rattlervault"
            with self.assertRaisesRegex(ValueError, "at least 12 characters"):
                export_bundle(store, bundle, "too short", apply=True)
            bundle.write_bytes(b"existing")
            with self.assertRaisesRegex(ValueError, "already exists"):
                export_bundle(store, bundle, "correct horse battery", apply=True)
            self.assertEqual(bundle.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main()
