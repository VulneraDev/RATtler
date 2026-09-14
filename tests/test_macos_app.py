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
        self.assertEqual(info["CFBundleShortVersionString"], "0.7.0")
        self.assertEqual(info["LSMinimumSystemVersion"], "13.0")
        self.assertTrue(info["LSMultipleInstancesProhibited"])

    def test_interface_is_local_and_has_required_views(self):
        html = (APP / "Resources/Web/index.html").read_text(encoding="utf-8")
        script = (APP / "Resources/Web/app.js").read_text(encoding="utf-8")
        self.assertIn("connect-src 'none'", html)
        for view in ("dashboard", "findings", "sensors", "activity", "settings"):
            self.assertIn('id="%s"' % view, html)
        for handler in ("receiveReport", "receiveCapabilities", "receiveState"):
            self.assertIn(handler, script)

    def test_native_host_does_not_invoke_a_shell(self):
        host = (APP / "Sources/main.m").read_text(encoding="utf-8")
        self.assertIn("NSTask", host)
        self.assertNotIn("/bin/sh", host)
        self.assertNotIn("system(", host)

    def test_readme_screenshots_are_reproducible_pngs(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for state in ("healthy", "risk"):
            relative = "docs/images/rattler-%s.png" % state
            image = (ROOT / relative).read_bytes()
            self.assertIn(relative, readme)
            self.assertEqual(image[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(struct.unpack(">II", image[16:24]), (1180, 760))
            with (ROOT / "docs/fixtures" / ("ui-%s.json" % state)).open() as handle:
                report = json.load(handle)
            self.assertIn(report["status"], {"healthy", "unhealthy"})


if __name__ == "__main__":
    unittest.main()
