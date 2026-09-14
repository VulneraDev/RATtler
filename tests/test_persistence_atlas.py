import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rattler.baseline import Fingerprint, check_baseline, create_baseline, write_baseline
from rattler.injection import SignatureInfo
from rattler.model import Status
from rattler.persistence_atlas import (
    _command_sources, _current_user_crontab, _login_item_trust, _metadata_findings,
    _parse_login_items, _plugin_trust, collect_atlas, _parse_configuration_profiles,
    persistence_atlas_sensor,
)
from rattler.runner import CommandResult


class PersistenceAtlasTests(unittest.TestCase):
    def test_shell_startup_detects_preload_and_temporary_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            startup = root / ".zshrc"
            startup.write_text("export LD_PRELOAD=/tmp/review.dylib\n/tmp/review-agent --background\n")
            check, findings = persistence_atlas_sensor(
                root, {"shell_startup": [root]}, include_commands=False,
            )
        self.assertEqual(check.status, Status.HEALTHY)
        self.assertEqual(check.details["items"], 1)
        self.assertEqual({item.rule_id for item in findings}, {"RAT-PERSIST-104", "RAT-PERSIST-105"})
        self.assertEqual(check.details["baseline_assets"], 1)

    def test_browser_manifest_records_context_and_insecure_updates(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "Default/Extensions/example/1.0/manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "name": "Example", "version": "1.0", "permissions": ["tabs"],
                "update_url": "http://updates.example.test/extension.xml",
            }))
            check, findings = persistence_atlas_sensor(
                Path(directory), {"browser_extensions": [Path(directory)]}, include_commands=False,
            )
        source = check.details["sources"][0]
        self.assertEqual(source["items"][0]["name"], "Example")
        self.assertEqual(source["items"][0]["permission_count"], 1)
        self.assertEqual([item.rule_id for item in findings], ["RAT-PERSIST-107"])

    def test_system_metadata_rules_are_deterministic(self):
        findings = _metadata_findings({
            "source": "periodic", "path": "/etc/periodic/review", "kind": "file",
            "mode": "0666", "uid": 501, "gid": 20, "symbolic_link": False,
        }, system_owned=True)
        self.assertEqual({item.rule_id for item in findings}, {"RAT-PERSIST-102", "RAT-PERSIST-103"})

    def test_symlink_is_reported_but_not_followed_or_baselined(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("safe")
            (root / ".zshrc").symlink_to(target)
            check, findings = persistence_atlas_sensor(
                root, {"shell_startup": [root]}, include_commands=False,
            )
        self.assertEqual([item.rule_id for item in findings], ["RAT-PERSIST-101"])
        self.assertEqual(check.details["baseline_assets"], 0)

    def test_symlinked_extension_bundle_is_not_followed_or_baselined(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            (target / "Contents").mkdir(parents=True)
            (target / "Contents/Info.plist").write_text("not followed")
            (root / "review.xcplugin").symlink_to(target)
            check, findings = persistence_atlas_sensor(
                root, {"developer_extensions": [root]}, include_commands=False,
            )
        self.assertEqual([item.rule_id for item in findings], ["RAT-PERSIST-101"])
        self.assertEqual(check.details["baseline_assets"], 0)

    @patch("rattler.persistence_atlas.MAX_VISITED_PATHS_PER_SOURCE", 2)
    def test_directory_traversal_has_a_global_source_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a", "b", "c"):
                (root / name).mkdir()
            check, findings = persistence_atlas_sensor(
                root, {"periodic": [root]}, include_commands=False,
            )
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertTrue(check.details["sources"][0]["limited"])
        self.assertEqual(findings, [])

    def test_one_unreadable_source_degrades_only_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("rattler.persistence_atlas.os.scandir", side_effect=PermissionError("denied")):
                check, findings = persistence_atlas_sensor(
                    root, {"periodic": [root]}, include_commands=False,
                )
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertEqual(check.details["sources_degraded"], ["periodic"])
        self.assertEqual(findings, [])

    def test_login_item_parser_is_bounded_and_structured(self):
        result = CommandResult(0, json.dumps({"SPLoginItemDataType": [{
            "_name": "Example", "path": "/Applications/Example.app", "status": "enabled",
            "ignored": "value",
        }]}), "")
        items, status, _message = _parse_login_items(result)
        self.assertEqual(status, "healthy")
        self.assertEqual(items, [{
            "source": "login_items", "kind": "login_item", "name": "Example",
            "path": "/Applications/Example.app", "status": "enabled",
        }])

    def test_configuration_profiles_are_bounded_to_safe_metadata(self):
        payload = plistlib.dumps({"_computerLevel": [{
            "ProfileDisplayName": "Endpoint Controls",
            "ProfileIdentifier": "dev.example.endpoint",
            "ProfileUUID": "00000000-0000-0000-0000-000000000000",
            "PayloadContent": [{"Secret": "not retained"}],
        }]})
        result = CommandResult(0, payload.decode("utf-8"), "")
        items, status, _message = _parse_configuration_profiles(result)
        self.assertEqual(status, "healthy")
        self.assertEqual(items, [{
            "source": "configuration_profiles", "kind": "configuration_profile",
            "scope": "device", "name": "Endpoint Controls",
            "identifier": "dev.example.endpoint",
            "uuid": "00000000-0000-0000-0000-000000000000",
        }])

    @patch("rattler.persistence_atlas.run")
    @patch("rattler.persistence_atlas.signature_info")
    def test_login_item_records_signing_and_notarization_as_context(self, mocked_signature, mocked_run):
        mocked_signature.return_value = SignatureInfo(True, "signed", "TEAM123456", "dev.example", "a" * 40)
        mocked_run.return_value = CommandResult(0, "accepted\nsource=Notarized Developer ID", "")
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Example.app"
            app.mkdir()
            findings, items = _login_item_trust([{
                "source": "login_items", "kind": "login_item", "name": "Example", "path": str(app),
            }])
        self.assertEqual(findings, [])
        self.assertTrue(items[0]["signature_valid"])
        self.assertEqual(items[0]["gatekeeper_assessment"], "accepted")
        self.assertTrue(items[0]["notarized"])

    @patch("rattler.persistence_atlas.run", return_value=CommandResult(1, "", "rejected"))
    @patch("rattler.persistence_atlas.signature_info", return_value=SignatureInfo(False, "unsigned"))
    def test_invalid_login_item_signing_has_a_precise_rule(self, _mocked_signature, _mocked_run):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Review.app"
            app.mkdir()
            findings, items = _login_item_trust([{
                "source": "login_items", "kind": "login_item", "name": "Review", "path": str(app),
            }])
        self.assertEqual([item.rule_id for item in findings], ["RAT-PERSIST-109"])
        self.assertEqual(items[0]["gatekeeper_assessment"], "rejected")

    @patch("rattler.persistence_atlas.run", return_value=CommandResult(1, "", "rejected"))
    @patch("rattler.persistence_atlas.signature_info", return_value=SignatureInfo(False, "adhoc"))
    def test_invalid_authorization_plugin_signing_has_a_precise_rule(self, _mocked_signature, _mocked_run):
        findings, items = _plugin_trust([{
            "source": "authorization_plugins", "kind": "bundle", "path": "/Library/Security/SecurityAgentPlugins/Review.bundle",
        }])
        self.assertEqual([item.rule_id for item in findings], ["RAT-PERSIST-106"])
        self.assertFalse(items[0]["signature_valid"])

    @patch("rattler.persistence_atlas.run")
    def test_risky_login_item_path_is_reported_without_needing_file_content(self, mocked_run):
        empty_profiles = plistlib.dumps({}).decode("utf-8")

        def command_result(command, timeout=10.0):
            del timeout
            if command[0] == "/usr/sbin/system_profiler":
                return CommandResult(0, json.dumps({"SPLoginItemDataType": [{
                    "_name": "Review", "path": "/tmp/Review.app", "status": "enabled",
                }]}), "")
            if command[:2] == ["/usr/bin/profiles", "list"]:
                return CommandResult(0, empty_profiles, "")
            return CommandResult(0, "enabled", "")

        mocked_run.side_effect = command_result
        _sources, findings = _command_sources()
        self.assertIn("RAT-PERSIST-108", {item.rule_id for item in findings})

    @patch("rattler.persistence_atlas.run")
    def test_current_user_crontab_does_not_return_command_contents(self, mocked_run):
        mocked_run.return_value = CommandResult(0, "* * * * * /tmp/review-agent --secret token", "")
        items, findings, errors = _current_user_crontab()
        self.assertEqual(errors, [])
        self.assertEqual(items[0]["staging_path_reference"], True)
        self.assertNotIn("command", items[0])
        self.assertEqual([item.rule_id for item in findings], ["RAT-PERSIST-104"])

    @patch("rattler.persistence_atlas.run")
    def test_current_user_crontab_merges_without_becoming_a_file_asset(self, mocked_run):
        def command_result(command, timeout=10.0):
            del timeout
            if command[:2] == ["/usr/bin/crontab", "-l"]:
                return CommandResult(0, "* * * * * /usr/bin/true", "")
            if command[0] == "/usr/sbin/system_profiler":
                return CommandResult(0, '{"SPLoginItemDataType": []}', "")
            return CommandResult(0, "enabled", "")

        mocked_run.side_effect = command_result
        sources, findings, assets = collect_atlas(
            Path("/nonexistent"), {"cron": []}, include_commands=True,
        )
        cron = next(item for item in sources if item["id"] == "cron")
        self.assertEqual(cron["items"][0]["kind"], "current_user_crontab")
        self.assertEqual(findings, [])
        self.assertEqual(assets, [])

    def test_manual_baseline_tracks_atlas_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "home"
            root.mkdir()
            startup = root / ".zshrc"
            startup.write_text("export SAFE=value\n")
            baseline = Path(directory) / "baseline.json"
            create_baseline(
                baseline, launchd_roots=[], include_loaded_code=False,
                atlas_roots={"shell_startup": [root]},
            )
            startup.write_text("export SAFE=changed\n")
            check, findings = check_baseline(
                baseline, launchd_roots=[], include_loaded_code=False,
                atlas_roots={"shell_startup": [root]},
            )
        self.assertEqual(check.status, Status.HEALTHY)
        self.assertEqual(findings[0].rule_id, "RAT-BASE-002")
        self.assertEqual(findings[0].evidence["kind"], "atlas_shell_startup")

    def test_unavailable_atlas_kind_does_not_become_a_false_missing_finding(self):
        entry = Fingerprint("/private/source/item", "atlas_cron", "abc", 1, 0o600, 0, 0)
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            write_baseline(baseline, [entry])
            with patch("rattler.baseline._discover_assets_with_coverage", return_value=([], {"atlas_cron"})):
                check, findings = check_baseline(baseline)
        self.assertEqual(check.status, Status.DEGRADED)
        self.assertEqual(check.details["unavailable_kinds"], ["atlas_cron"])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
