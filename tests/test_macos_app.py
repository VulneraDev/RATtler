import json
import plistlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app/macos"


class MacOSAppSourceTests(unittest.TestCase):
    def test_bundle_metadata_matches_release(self):
        with (APP / "Info.plist").open("rb") as handle:
            info = plistlib.load(handle)
        self.assertEqual(info["CFBundleIdentifier"], "dev.vulnera.rattler")
        self.assertEqual(info["CFBundleShortVersionString"], "0.11.0")
        self.assertEqual(info["CFBundleVersion"], "13")
        self.assertEqual(info["LSMinimumSystemVersion"], "13.0")
        self.assertTrue(info["LSMultipleInstancesProhibited"])

    def test_interface_is_local_and_has_required_views(self):
        html = (APP / "Resources/Web/index.html").read_text(encoding="utf-8")
        script = (APP / "Resources/Web/app.js").read_text(encoding="utf-8")
        self.assertIn("connect-src 'none'", html)
        for view in ("dashboard", "findings", "ransomware", "bluepulse", "activity", "settings"):
            self.assertIn('id="%s"' % view, html)
        for handler in ("receiveReport", "receiveCapabilities", "receiveState", "receiveResponse"):
            self.assertIn(handler, script)
        self.assertIn("Detection confidence", script)
        self.assertIn("collector heartbeat", script)
        self.assertIn("No encryption pattern detected", script)
        self.assertIn("Automatic write blocking is not enabled", script)
        self.assertIn("Recovery Vault is active", script)
        self.assertIn("never overwrites originals", script)

    def test_quarantine_requires_native_review_and_exact_hash(self):
        host = (APP / "Sources/main.m").read_text(encoding="utf-8")
        self.assertIn('alert.messageText = @"Quarantine this exact file?"', host)
        self.assertIn('@"--expected-sha256", digest, @"--apply"', host)
        self.assertIn('@"response", @"quarantine", path', host)
        self.assertIn('if ([alert runModal] != NSAlertFirstButtonReturn)', host)
        self.assertIn('alert.messageText = @"Restore this quarantined file?"', host)
        self.assertIn('@"response", @"restore", identifier', host)

    def test_app_excludes_only_its_process_id_and_explains_installation(self):
        host = (APP / "Sources/main.m").read_text(encoding="utf-8")
        script = (APP / "Resources/Web/app.js").read_text(encoding="utf-8")
        self.assertIn('@"--exclude-pid", [NSString stringWithFormat:@"%d", getpid()]', host)
        self.assertIn('@"installed": @(installed)', host)
        self.assertIn("Finish installing RATtler", script)
        self.assertNotIn("excluded_process_name", host)

    def test_app_enables_bounded_ransomware_monitoring(self):
        host = (APP / "Sources/main.m").read_text(encoding="utf-8")
        script = (APP / "Resources/Web/app.js").read_text(encoding="utf-8")
        self.assertIn('@"--ransomware-state", ransomwareState.path', host)
        for folder in ("Desktop", "Documents", "Pictures"):
            self.assertIn('@"%s"' % folder, host)
        self.assertIn('storedAuto===null?true', script)

    def test_recovery_requires_native_consent_and_uses_a_new_destination(self):
        host = (APP / "Sources/main.m").read_text(encoding="utf-8")
        self.assertIn('alert.messageText = @"Enable the Recovery Vault?"', host)
        self.assertIn('@"recovery", @"backup"', host)
        self.assertIn('alert.messageText = @"Recover protected copies?"', host)
        self.assertIn('@"recovery", @"restore-all"', host)
        self.assertIn('@"RATtler Recovered %@"', host)
        self.assertIn('freezeRecoveryForReport', host)

    def test_download_and_gatekeeper_instructions_are_plain(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        build = (APP / "build.sh").read_text(encoding="utf-8")
        self.assertIn("Download **one ZIP**", readme)
        self.assertIn("releases/download/v0.11.0/RATtler-macOS-Apple-Silicon.zip", readme)
        self.assertIn("releases/download/v0.11.0/RATtler-macOS-Intel.zip", readme)
        self.assertIn("System Settings → Privacy & Security", readme)
        self.assertIn("Open Anyway", readme)
        self.assertIn('release_architecture="Apple-Silicon"', build)
        self.assertIn('release_architecture="Intel"', build)

    def test_native_host_does_not_invoke_a_shell(self):
        host = (APP / "Sources/main.m").read_text(encoding="utf-8")
        self.assertIn("NSTask", host)
        self.assertNotIn("/bin/sh", host)
        self.assertNotIn("system(", host)

    def test_readme_screenshots_are_reproducible_pngs(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        fixtures = {"healthy": "healthy", "risk": "risk", "bluepulse": "healthy", "ransomware": "healthy"}
        for state, fixture in fixtures.items():
            relative = "docs/images/rattler-%s.png" % state
            image = (ROOT / relative).read_bytes()
            self.assertIn(relative, readme)
            self.assertEqual(image[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(struct.unpack(">II", image[16:24]), (1180, 760))
            with (ROOT / "docs/fixtures" / ("ui-%s.json" % fixture)).open() as handle:
                report = json.load(handle)
            self.assertIn(report["status"], {"healthy", "unhealthy"})


if __name__ == "__main__":
    unittest.main()
