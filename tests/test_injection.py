import unittest
from unittest.mock import patch

from rattler.behavior import ProcessInfo
from rattler.injection import (
    LoadedImage,
    SignatureInfo,
    analyze_loaded_images,
    parse_loaded_images,
    signature_info,
    signature_metadata,
)
from rattler.runner import CommandResult
from rattler.model import Severity


class LoadedImageParsingTests(unittest.TestCase):
    def test_parses_only_regular_text_mappings_and_deduplicates(self):
        output = (
            "p42\nctrusted\nftxt\ntREG\nn/Applications/Trusted.app/Contents/MacOS/Trusted\n"
            "ftxt\ntREG\nn/tmp/inject.dylib\nn/tmp/inject.dylib\n"
            "f1\ntREG\nn/tmp/not-a-text-mapping\n"
        )
        self.assertEqual(parse_loaded_images(output), [
            LoadedImage(42, "trusted", "/Applications/Trusted.app/Contents/MacOS/Trusted"),
            LoadedImage(42, "trusted", "/tmp/inject.dylib"),
        ])


class LoadedImageAnalysisTests(unittest.TestCase):
    @patch("rattler.injection.is_macho", return_value=True)
    @patch("rattler.injection.verify_signature", return_value=False)
    @patch("rattler.injection.signature_metadata")
    def test_flags_unsigned_temp_module_in_protected_process(self, mocked_signature, _verify, _macho):
        mocked_signature.side_effect = lambda path: (
            SignatureInfo(False, "unsigned") if path == "/tmp/inject.dylib"
            else SignatureInfo(True, "signed", "TRUSTED")
        )
        processes = {42: ProcessInfo(42, 1, "/Applications/Trusted.app/Contents/MacOS/Trusted")}
        images = [LoadedImage(42, "Trusted", "/tmp/inject.dylib")]
        findings, inspected = analyze_loaded_images(images, processes, "/Users/test")
        self.assertEqual(inspected, 1)
        self.assertEqual(findings[0].rule_id, "RAT-INJECT-003")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_flags_deleted_module_in_protected_process(self):
        processes = {42: ProcessInfo(42, 1, "/Applications/Trusted.app/Contents/MacOS/Trusted")}
        images = [LoadedImage(42, "Trusted", "/tmp/inject.dylib (deleted)")]
        findings, inspected = analyze_loaded_images(images, processes, "/Users/test")
        self.assertEqual(inspected, 0)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    @patch("rattler.injection.is_macho")
    def test_skips_module_inside_its_host_app_bundle(self, mocked_macho):
        host = "/Users/test/Tools/Trusted.app/Contents/MacOS/Trusted"
        module = "/Users/test/Tools/Trusted.app/Contents/Frameworks/Helper.dylib"
        processes = {42: ProcessInfo(42, 1, host)}
        findings, inspected = analyze_loaded_images(
            [LoadedImage(42, "Trusted", module)], processes, "/Users/test"
        )
        self.assertEqual((findings, inspected), ([], 0))
        mocked_macho.assert_not_called()

    @patch("rattler.injection.is_macho", return_value=True)
    @patch("rattler.injection.signature_metadata")
    def test_ignores_same_team_signed_user_module(self, mocked_signature, _macho):
        mocked_signature.return_value = SignatureInfo(True, "signed", "SAME-TEAM")
        processes = {42: ProcessInfo(42, 1, "/Applications/Trusted.app/Contents/MacOS/Trusted")}
        images = [LoadedImage(42, "Trusted", "/Users/test/Library/Application Support/Trusted/plugin.dylib")]
        findings, inspected = analyze_loaded_images(images, processes, "/Users/test")
        self.assertEqual(inspected, 1)
        self.assertEqual(findings, [])

    @patch("rattler.injection.is_macho", return_value=True)
    @patch("rattler.injection.verify_signature", return_value=True)
    @patch("rattler.injection.signature_metadata")
    def test_flags_translocated_executable_with_cdhash(self, mocked_signature, _verify, _macho):
        path = "/private/var/folders/ab/cd/T/AppTranslocation/UUID/d/Test.app/Contents/MacOS/Test"
        mocked_signature.return_value = SignatureInfo(
            True, "signed", "TEAM123", "dev.example.test", "a" * 40,
        )
        findings, inspected = analyze_loaded_images(
            [LoadedImage(42, "Test", path)], {42: ProcessInfo(42, 1, path)}, "/Users/test",
        )
        self.assertEqual(inspected, 1)
        self.assertEqual(findings[0].rule_id, "RAT-INJECT-004")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertEqual(findings[0].evidence["module_cdhash"], "a" * 40)
        self.assertTrue(findings[0].evidence["app_translocated"])


class SignatureTests(unittest.TestCase):
    @patch("rattler.injection.run")
    def test_signature_metadata_records_valid_cdhash(self, mocked_run):
        mocked_run.return_value = CommandResult(
            0, "", "Identifier=dev.example.test\nTeamIdentifier=TEAM123\nCDHash=" + "A1" * 20,
        )
        result = signature_metadata("/Applications/Test.app")
        self.assertEqual(result.cdhash, "a1" * 20)

    @patch("rattler.injection.run")
    def test_apple_platform_signature_is_not_treated_as_adhoc(self, mocked_run):
        mocked_run.side_effect = [
            CommandResult(0, "", "Identifier=com.apple.test\nPlatform identifier=15\nTeamIdentifier=not set"),
            CommandResult(0, "", ""),
        ]
        result = signature_info("/usr/libexec/example")
        self.assertTrue(result.valid)
        self.assertEqual(result.kind, "signed")


if __name__ == "__main__":
    unittest.main()
