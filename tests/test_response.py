import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from rattler.cli import main as cli_main
from rattler.response import ResponseError, _is_protected, list_quarantine, quarantine_file, restore_file


class QuarantineTests(unittest.TestCase):
    def test_dry_run_returns_hash_without_moving_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "sample.bin"
            target.write_bytes(b"safe fixture")
            result = quarantine_file(target, "review suspicious file", root / "store")
            self.assertFalse(result["applied"])
            self.assertEqual(result["sha256"], hashlib.sha256(b"safe fixture").hexdigest())
            self.assertTrue(target.exists())
            self.assertFalse((root / "store").exists())

    def test_apply_requires_matching_dry_run_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "sample.bin"
            target.write_bytes(b"version one")
            with self.assertRaisesRegex(ResponseError, "requires the SHA-256"):
                quarantine_file(target, "operator review", root / "store", apply=True)
            with self.assertRaisesRegex(ResponseError, "no longer matches"):
                quarantine_file(
                    target,
                    "operator review",
                    root / "store",
                    "0" * 64,
                    apply=True,
                )
            self.assertEqual(target.read_bytes(), b"version one")

    def test_quarantine_list_and_restore_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "store"
            target = root / "agent"
            target.write_bytes(b"inert test payload")
            target.chmod(0o755)
            plan = quarantine_file(target, "safe response test", store)
            applied = quarantine_file(
                target,
                "safe response test",
                store,
                plan["sha256"],
                apply=True,
            )
            self.assertFalse(target.exists())
            payload = Path(applied["payload"])
            self.assertEqual(payload.read_bytes(), b"inert test payload")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(store.stat().st_mode), 0o700)
            entries = list_quarantine(store)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["status"], "quarantined")

            restore_plan = restore_file(applied["id"], store)
            self.assertFalse(restore_plan["applied"])
            restored = restore_file(applied["id"], store, apply=True)
            self.assertEqual(restored["status"], "restored")
            self.assertEqual(target.read_bytes(), b"inert test payload")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            audit = [json.loads(line) for line in (store / "audit.jsonl").read_text().splitlines()]
            self.assertEqual([event["action"] for event in audit], ["quarantine", "restore"])

    def test_refuses_links_directories_and_protected_paths(self):
        self.assertTrue(_is_protected(Path("/System/Library/example")))
        self.assertTrue(_is_protected(Path("/usr/bin/example")))
        self.assertFalse(_is_protected(Path("/Users/example/Downloads/example")))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular"
            regular.write_bytes(b"fixture")
            symbolic = root / "symbolic"
            try:
                symbolic.symlink_to(regular)
            except OSError:
                pass  # Unprivileged Windows CI may not permit symbolic links.
            else:
                with self.assertRaisesRegex(ResponseError, "Symbolic|symbolic"):
                    quarantine_file(symbolic, "test", root / "store")
            with self.assertRaisesRegex(ResponseError, "regular file"):
                quarantine_file(root, "test", root / "store")
            hardlink = root / "hardlink"
            os.link(str(regular), str(hardlink))
            with self.assertRaisesRegex(ResponseError, "Hard-linked|hard-linked"):
                quarantine_file(regular, "test", root / "store")

    def test_restore_refuses_to_overwrite_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "store"
            target = root / "agent"
            target.write_bytes(b"original")
            plan = quarantine_file(target, "collision test", store)
            applied = quarantine_file(
                target, "collision test", store, plan["sha256"], apply=True
            )
            target.write_bytes(b"replacement")
            with self.assertRaisesRegex(ResponseError, "already exists"):
                restore_file(applied["id"], store, apply=True)
            self.assertEqual(target.read_bytes(), b"replacement")

    def test_restore_refuses_corrupted_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "store"
            target = root / "agent"
            target.write_bytes(b"reviewed content")
            plan = quarantine_file(target, "integrity test", store)
            applied = quarantine_file(
                target, "integrity test", store, plan["sha256"], apply=True
            )
            Path(applied["payload"]).write_bytes(b"changed after quarantine")
            with self.assertRaisesRegex(ResponseError, "integrity verification"):
                restore_file(applied["id"], store, apply=True)
            self.assertFalse(target.exists())

    def test_audit_hardlink_refusal_rolls_back_quarantine(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "store"
            (store / "entries").mkdir(parents=True)
            audit = store / "audit.jsonl"
            audit.write_text("")
            os.link(str(audit), str(root / "linked-audit"))
            target = root / "agent"
            target.write_bytes(b"rollback fixture")
            plan = quarantine_file(target, "audit test", store)
            with self.assertRaisesRegex(ResponseError, "without hard links"):
                quarantine_file(
                    target, "audit test", store, plan["sha256"], apply=True
                )
            self.assertEqual(target.read_bytes(), b"rollback fixture")
            self.assertEqual(list((store / "entries").iterdir()), [])

    def test_tampered_manifest_cannot_restore_to_protected_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "store"
            target = root / "agent"
            target.write_bytes(b"manifest fixture")
            plan = quarantine_file(target, "manifest test", store)
            applied = quarantine_file(
                target, "manifest test", store, plan["sha256"], apply=True
            )
            manifest_path = store / "entries" / applied["id"] / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["original_path"] = "/System/Library/rattler-test"
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ResponseError, "protected"):
                restore_file(applied["id"], store, apply=True)


class ResponseCLITests(unittest.TestCase):
    def test_cli_requires_review_before_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "sample"
            store = root / "store"
            target.write_bytes(b"cli fixture")
            output = io.StringIO()
            with redirect_stdout(output):
                result = cli_main([
                    "response", "quarantine", str(target),
                    "--reason", "CLI review", "--store", str(store),
                ])
            self.assertEqual(result, 0)
            plan = json.loads(output.getvalue())
            self.assertFalse(plan["applied"])

            error = io.StringIO()
            with redirect_stderr(error):
                result = cli_main([
                    "response", "quarantine", str(target),
                    "--reason", "CLI review", "--store", str(store), "--apply",
                ])
            self.assertEqual(result, 2)
            self.assertIn("requires the SHA-256", error.getvalue())


if __name__ == "__main__":
    unittest.main()
