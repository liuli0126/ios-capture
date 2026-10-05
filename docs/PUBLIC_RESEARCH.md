# Public research used by iOS Capture

This note records the public implementations checked while adapting the iOS 15+
rootless capture build for Douyin and TikTok. Runtime behavior still depends on
the exact target App version.

## Findings

1. ByteDance's public `TTHttpTask` header exposes `skipSSLCertificateError` and
   states that it applies to the Chromium implementation. This is a stable
   target for TTNet builds that retain the Objective-C class and selector.
2. Older TikTok and Douyin scripts also use `TTHttpTask` and
   `TTNetworkManagerChromium.ServerCertificate`. The latter has changed across
   App releases, so it is installed only when the class and selector exist.
3. Modern rootless trust bypasses cover asynchronous Security.framework calls,
   `sec_protocol_options_set_verify_block`, and public `NSURLSession` challenge
   delegates in addition to the synchronous trust APIs.
4. Dopamine uses ElleKit. A directly injected dylib must resolve
   `MSHookFunction` from `libellekit.dylib`; looking only for Substrate can leave
   every C Hook inactive while the target App still launches normally.
5. ByteDance's public TTNetworkManager framework includes `BDQuicConfig` and
   Cronet/QUIC headers. A conventional HTTP proxy cannot decrypt QUIC, so the
   plugin disables known QUIC configuration and UDP/443 to request HTTP/2
   fallback.
6. Current public patched TikTok builds describe separate Cronet/TTNet and
   `libvcn` pinning paths. There is no public source for their binary patches,
   so `libvcn` remains version-specific work if the public selectors and exported
   native TLS symbols are absent.
7. The public Douyin TTNetworkManager script returns `nil` from both
   `TTNetworkManager.ServerCertificate` implementations. Returning an empty
   array is not equivalent and can leave the Chromium pin list enabled with no
   acceptable certificate.
8. `TTHttpTask` retains a public `resume` method and a concrete
   `_skipSSLCertificateError` property. Setting the property immediately before
   `resume` covers tasks created before the runtime scan installs its getter hook.
9. SSL Kill Switch 3 strips authenticated arm64e function addresses before
   passing them to `MSHookFunction`; the BoringSSL custom-verify callback remains
   a typed function pointer so the compiler emits the required pointer
   authentication metadata.

## Sources

- [BytePlus TTNetworkManager TTHttpTask header](https://github.com/byteplus-sdk/BPLive_SPM/blob/c46fd6061985dd139cdd29e3ce47969acf85255b/Frameworks/Vendor/TTNetworkManager.xcframework/ios-arm64/TTNetworkManager.framework/Headers/TTHttpTask.h)
- [BytePlus BDQuicConfig header](https://github.com/byteplus-sdk/BPLive_SPM/blob/c46fd6061985dd139cdd29e3ce47969acf85255b/Frameworks/Vendor/TTNetworkManager.xcframework/ios-arm64/TTNetworkManager.framework/Headers/BDQuicConfig.h)
- [OFFSET Trust Bypass](https://github.com/r3352/offset-trust-bypass/tree/0cee0f40fb1b1c43765a063cfc2b9f198ea64455)
- [SSL Kill Switch 3](https://github.com/NyaMisty/ssl-kill-switch3/tree/665ad3aa09ca3066799e93713eea6bf517adcaa8)
- [TTNetworkManager TikTok Frida example](https://github.com/paradiseduo/TTNetworkManager/tree/7fce7e5a0e4f9cf14c8494ecf46a261ed34c0637)
- [Douyin iOS capture notes](https://github.com/crifan/mobile_re_capture_bypass_limit/blob/9dc9d03d4d0e71db4014199fc0b6687979f00fd6/src/other_special/dy/ios/README.md)
- [TikTok iOS patched build description](https://github.com/0xSHAK1B/TikTok-iOS-SSL-Pinning-Bypass/tree/a6402bd502f084c35d84d4f4066c8476a35ab5e7)

## Test gate

The status banner proves only that the Hook runtime was found and functions were
patched. The capture path must still be checked in this order:

1. Safari request visible and decrypted in ProxyPin.
2. Target App request visible after direct injection.
3. Target App HTTPS body decrypted.
4. If only some video or live endpoints remain opaque, collect the exact App
   version and identify its `libvcn` image before adding a version adapter.
