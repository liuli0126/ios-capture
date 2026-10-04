import plistlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ProjectTests(unittest.TestCase):
    def test_manager_identity_and_minimum_ios(self):
        with (ROOT / "manager" / "Resources" / "Info.plist").open("rb") as handle:
            info = plistlib.load(handle)
        self.assertEqual(info["CFBundleIdentifier"], "com.ioscapture.manager")
        self.assertEqual(info["MinimumOSVersion"], "13.0")

    def test_preferences_are_shared_by_manager_and_tweak(self):
        preferences = (ROOT / "shared" / "ICPreferences.m").read_text(encoding="utf-8")
        manager = (ROOT / "manager" / "RootViewController.m").read_text(encoding="utf-8")
        tweak = (ROOT / "tweak" / "Tweak.xm").read_text(encoding="utf-8")
        self.assertIn('ICPreferencesDomain = @"com.ioscapture.settings"', preferences)
        self.assertIn("ICSetSelectedBundleIdentifiers", manager)
        self.assertIn("ICIsCurrentProcessSelected", tweak)
        self.assertLess(tweak.index("ICIsCurrentProcessSelected"), tweak.index("ICInstallTLSHooks"))

    def test_subprojects_include_shared_headers_from_project_root(self):
        for relative_makefile in ("tweak/Makefile", "manager/Makefile"):
            makefile = (ROOT / relative_makefile).read_text(encoding="utf-8")
            self.assertIn("-I$(THEOS_PROJECT_DIR)/shared", makefile)
            self.assertNotIn("-I$(THEOS_PROJECT_DIR)/../shared", makefile)

        header = (ROOT / "shared" / "ICPreferences.h").read_text(encoding="utf-8")
        self.assertIn("id _Nullable ICCopyPreference", header)
        self.assertNotRegex(header, r"\bnullable\s+id\b")
        self.assertIn('extern "C" {', header)

    def test_tls_hook_coverage(self):
        source = (ROOT / "tweak" / "ICTLSHooks.mm").read_text(encoding="utf-8")
        expected = {
            "SecTrustEvaluate",
            "SecTrustEvaluateWithError",
            "SecTrustGetTrustResult",
            "AFSecurityPolicy",
            "TSKPinningValidator",
            "SSL_set_custom_verify",
            "SSL_CTX_set_custom_verify",
            "SSL_get_verify_result",
        }
        missing = {marker for marker in expected if marker not in source}
        self.assertFalse(missing)

    def test_tweak_filter_avoids_daemons(self):
        filter_text = (ROOT / "tweak" / "iOSCaptureHook.plist").read_text(encoding="utf-8")
        self.assertRegex(filter_text, r'Classes\s*=\s*\("UIApplication"\)')
        self.assertNotIn("Executables", filter_text)
        self.assertNotIn("mediaserverd", filter_text)
        self.assertNotIn("SpringBoard", filter_text)

    def test_rootful_and_rootless_controls(self):
        rootless = (ROOT / "control").read_text(encoding="utf-8")
        rootful = (ROOT / "control.rootful").read_text(encoding="utf-8")
        self.assertIn("Architecture: iphoneos-arm64", rootless)
        self.assertIn("firmware (>= 15.0)", rootless)
        self.assertIn("Architecture: iphoneos-arm", rootful)
        self.assertIn("firmware (>= 13.0)", rootful)
        for control in (rootless, rootful):
            self.assertIn("Package: com.ioscapture", control)
            self.assertRegex(control, r"(?m)^Version: 0\.1\.0$")

    def test_project_sources_do_not_depend_on_applelive(self):
        source_roots = (ROOT / "shared", ROOT / "tweak", ROOT / "manager")
        files = [path for directory in source_roots for path in directory.rglob("*") if path.is_file()]
        matches = []
        for path in files:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"AppleLive", text, re.IGNORECASE):
                matches.append(str(path.relative_to(ROOT)))
        self.assertEqual(matches, [])


if __name__ == "__main__":
    unittest.main()
