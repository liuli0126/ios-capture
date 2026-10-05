# Changelog

## 0.1.7 - 2026-10-05

- Restore the stable delayed direct-injection startup sequence used by v0.1.5.
- Disable BoringSSL callback replacement on arm64e after the v0.1.6 runtime crash report.
- Keep the TTNet certificate-list, task-resume, generic selector, and categorized diagnostics fixes.

## 0.1.6 - 2026-10-05

- Install direct-injection hooks during process construction so TTNet startup configuration is not missed.
- Return `nil` for `TTNetworkManager` server-certificate lists and block later pin-list setters.
- Force `TTHttpTask.skipSSLCertificateError` again immediately before `resume`.
- Restore BoringSSL custom-verify hooks on arm64e with authenticated targets stripped before ElleKit patching.
- Show installed and runtime-hit counts separately for system TLS, URLSession, TTNet, native TLS, and QUIC.

## 0.1.5 - 2026-10-05

- Resolve `MSHookFunction` directly from Dopamine's rootless ElleKit runtime.
- Rescan TLS and Objective-C hooks whenever a new Mach-O image is loaded.
- Add asynchronous Security.framework and Network.framework verification hooks.
- Add public `NSURLSession` server-trust delegate interception.
- Add TTNet compatibility for `TTHttpTask` and `TTNetworkManagerChromium`.
- Add optional HTTP/3 fallback by disabling known QUIC configuration objects and UDP/443.
- Add a short direct-injection status banner showing Hook runtime availability and installed Hook count.

## 0.1.4 - 2026-10-05

- Replaced direct-injection fishhook startup with delayed runtime resolution of the existing Dopamine Hook API.
- Direct injection now skips C function Hooks when the runtime API is unavailable instead of failing App startup.
- Paused automatic iOS 13 builds while iOS 15+ direct injection is stabilized.

## 0.1.3 - 2026-10-05

- Removed the Substrate load dependency from direct-injection dylibs.
- Added standalone fishhook symbol rebinding and Objective-C runtime method replacement for TrollStore injection tools.
- Removed preference writes from the direct-injection startup path.

## 0.1.2 - 2026-10-05

- Added explicit Douyin and TikTok bundle filters for reliable ElleKit injection.
- Split dylib loading and active Hook status so injection and preference failures can be distinguished.
- Clear stale injection status whenever the selected targets are applied.
- Added direct-injection dylibs for TrollStore injection tools; these bypass target selection and enable native TLS automatically.

## 0.1.1 - 2026-10-05

- Replaced the early `UIApplication` class filter with an ElleKit-compatible UIKit bundle filter.
- Added package verification that rejects the ineffective class filter.

## 0.1.0 - 2026-10-04

- Added a standalone jailbreak iOS packet-capture companion project.
- Added target App selection and shared preferences.
- Added Security.framework, AFNetworking and TrustKit TLS hooks.
- Added optional dynamically linked BoringSSL/OpenSSL hooks.
- Added ProxyPin launch and target process restart controls.
- Added rootless iOS 15+ and rootful iOS 13 build workflows.
- Added source, package-layout and legacy arm64e ABI checks.
