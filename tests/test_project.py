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
        self.assertEqual(info["CFBundleShortVersionString"], "0.1.3")

        makefile = (ROOT / "manager" / "Makefile").read_text(encoding="utf-8")
        self.assertIn("-S$(THEOS_PROJECT_DIR)/manager/Entitlements.plist", makefile)
        self.assertTrue((ROOT / "manager" / "Entitlements.plist").is_file())

    def test_preferences_are_shared_by_manager_and_tweak(self):
        preferences = (ROOT / "shared" / "ICPreferences.m").read_text(encoding="utf-8")
        manager = (ROOT / "manager" / "RootViewController.m").read_text(encoding="utf-8")
        tweak = (ROOT / "tweak" / "Tweak.xm").read_text(encoding="utf-8")
        self.assertIn('ICPreferencesDomain = @"com.ioscapture.settings"', preferences)
        self.assertIn("ICSetSelectedBundleIdentifiers", manager)
        self.assertIn("ICIsCurrentProcessSelected", tweak)
        self.assertIn("ICMarkCurrentProcessLoaded", tweak)
        self.assertLess(tweak.index("ICMarkCurrentProcessLoaded"), tweak.index("ICIsCurrentProcessSelected"))
        automatic_branch = tweak.split("#else", 1)[1].split("#endif", 1)[0]
        self.assertLess(automatic_branch.index("ICIsCurrentProcessSelected"),
                        automatic_branch.index("ICInstallTLSHooks"))

    def test_subprojects_include_shared_headers_from_project_root(self):
        for relative_makefile in ("tweak/Makefile", "manager/Makefile"):
            makefile = (ROOT / relative_makefile).read_text(encoding="utf-8")
            self.assertIn("-I$(THEOS_PROJECT_DIR)/shared", makefile)
            self.assertNotIn("-I$(THEOS_PROJECT_DIR)/../shared", makefile)

        header = (ROOT / "shared" / "ICPreferences.h").read_text(encoding="utf-8")
        self.assertIn("id _Nullable ICCopyPreference", header)
        self.assertNotRegex(header, r"\bnullable\s+id\b")
        self.assertIn('extern "C" {', header)

    def test_package_verifier_parses_compiled_plists(self):
        verifier = (ROOT / "scripts" / "verify_package.py").read_text(encoding="utf-8")
        self.assertIn("plistlib.load(handle)", verifier)
        self.assertNotIn("filter_plist.read_text", verifier)

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
        with (ROOT / "tweak" / "iOSCaptureHook.plist").open("rb") as handle:
            filter_configuration = plistlib.load(handle)
        filter_rules = filter_configuration["Filter"]
        self.assertIn("com.apple.UIKit", filter_rules["Bundles"])
        self.assertIn("com.ss.iphone.ugc.Aweme", filter_rules["Bundles"])
        self.assertIn("com.zhiliaoapp.musically", filter_rules["Bundles"])
        self.assertNotIn("Classes", filter_rules)
        self.assertNotIn("Executables", filter_rules)

        with (ROOT / "tweak" / "iOSCaptureDirect.plist").open("rb") as handle:
            direct_filter = plistlib.load(handle)["Filter"]
        self.assertEqual(direct_filter["Bundles"], ["com.ioscapture.direct.manual-only"])

    def test_direct_injection_build_does_not_require_target_selection(self):
        makefile = (ROOT / "tweak" / "Makefile").read_text(encoding="utf-8")
        tweak = (ROOT / "tweak" / "Tweak.xm").read_text(encoding="utf-8")
        hooks = (ROOT / "tweak" / "ICTLSHooks.mm").read_text(encoding="utf-8")
        self.assertIn("TWEAK_NAME = iOSCaptureHook iOSCaptureDirect", makefile)
        self.assertIn("-DIOSCAPTURE_DIRECT_INJECTION=1", makefile)
        self.assertIn("third_party/fishhook/fishhook.c", makefile)
        self.assertNotIn("iOSCaptureDirect_LIBRARIES", makefile)
        self.assertIn("#if defined(IOSCAPTURE_DIRECT_INJECTION)", tweak)
        direct_branch = tweak.split("#if defined(IOSCAPTURE_DIRECT_INJECTION)", 1)[1].split("#else", 1)[0]
        self.assertIn("ICInstallTLSHooks", direct_branch)
        self.assertNotIn("ICIsCurrentProcessSelected", direct_branch)
        self.assertNotIn("ICMarkCurrentProcessLoaded", direct_branch)
        self.assertNotIn("ICMarkCurrentProcessInjected", direct_branch)
        self.assertIn("nativeTLSBypassEnabled = YES", hooks)
        self.assertIn("rebind_symbols", hooks)

    def test_rootful_and_rootless_controls(self):
        rootless = (ROOT / "control").read_text(encoding="utf-8")
        rootful = (ROOT / "control.rootful").read_text(encoding="utf-8")
        self.assertIn("Architecture: iphoneos-arm64", rootless)
        self.assertIn("firmware (>= 15.0)", rootless)
        self.assertIn("Architecture: iphoneos-arm", rootful)
        self.assertIn("firmware (>= 13.0)", rootful)
        for control in (rootless, rootful):
            self.assertIn("Package: com.ioscapture", control)
            self.assertRegex(control, r"(?m)^Version: 0\.1\.3$")

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
