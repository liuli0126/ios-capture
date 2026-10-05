#import "ICTLSHooks.h"

#import "ICPreferences.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#if defined(IOSCAPTURE_DIRECT_INJECTION)
#import "fishhook.h"
#else
#import <substrate.h>
#endif

static void ICLog(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);

static void ICLog(NSString *format, ...) {
#if !defined(IOSCAPTURE_DIRECT_INJECTION)
    if (!ICBoolPreference(ICDiagnosticsEnabledKey, YES)) {
        return;
    }
#endif

    va_list arguments;
    va_start(arguments, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);
    NSLog(@"[iOSCapture] %@", message);
}

static void *ICResolveSymbol(const char *name) {
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (symbol) {
        return symbol;
    }

    static void *securityHandle = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        securityHandle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    });
    return securityHandle ? dlsym(securityHandle, name) : NULL;
}

static BOOL ICInstallFunctionHook(const char *name, void *replacement, void **original) {
#if defined(IOSCAPTURE_DIRECT_INJECTION)
    struct rebinding binding = {name, replacement, original};
    return rebind_symbols(&binding, 1) == 0;
#else
    void *symbol = ICResolveSymbol(name);
    if (!symbol) {
        return NO;
    }
    MSHookFunction(symbol, replacement, original);
    return YES;
#endif
}

#pragma mark - Security.framework

static OSStatus (*ICOriginalSecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result) = NULL;
static OSStatus ICReplacementSecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) {
        *result = kSecTrustResultProceed;
    }
    return errSecSuccess;
}

static Boolean (*ICOriginalSecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef *error) = NULL;
static Boolean ICReplacementSecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    if (error) {
        *error = NULL;
    }
    return true;
}

static OSStatus (*ICOriginalSecTrustGetTrustResult)(SecTrustRef trust, SecTrustResultType *result) = NULL;
static OSStatus ICReplacementSecTrustGetTrustResult(SecTrustRef trust, SecTrustResultType *result) {
    if (result) {
        *result = kSecTrustResultProceed;
    }
    return errSecSuccess;
}

static NSUInteger ICInstallSecurityHooks(void) {
    NSUInteger count = 0;

    if (ICInstallFunctionHook("SecTrustEvaluate",
                              reinterpret_cast<void *>(&ICReplacementSecTrustEvaluate),
                              reinterpret_cast<void **>(&ICOriginalSecTrustEvaluate))) {
        count++;
    }

    if (ICInstallFunctionHook("SecTrustEvaluateWithError",
                              reinterpret_cast<void *>(&ICReplacementSecTrustEvaluateWithError),
                              reinterpret_cast<void **>(&ICOriginalSecTrustEvaluateWithError))) {
        count++;
    }

    if (ICInstallFunctionHook("SecTrustGetTrustResult",
                              reinterpret_cast<void *>(&ICReplacementSecTrustGetTrustResult),
                              reinterpret_cast<void **>(&ICOriginalSecTrustGetTrustResult))) {
        count++;
    }

    return count;
}

#pragma mark - AFNetworking and TrustKit

static BOOL (*ICOriginalAFEvaluate)(id self, SEL command, SecTrustRef trust, NSString *domain) = NULL;
static BOOL ICReplacementAFEvaluate(id self, SEL command, SecTrustRef trust, NSString *domain) {
    return YES;
}

static NSInteger (*ICOriginalTrustKitEvaluate)(id self, SEL command, SecTrustRef trust, NSString *hostname) = NULL;
static NSInteger ICReplacementTrustKitEvaluate(id self, SEL command, SecTrustRef trust, NSString *hostname) {
    return 0; // TSKTrustDecisionShouldAllowConnection
}

typedef void (^ICChallengeCompletion)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential *credential);
static BOOL (*ICOriginalTrustKitHandleChallenge)(id self,
                                                 SEL command,
                                                 NSURLAuthenticationChallenge *challenge,
                                                 ICChallengeCompletion completion) = NULL;
static BOOL ICReplacementTrustKitHandleChallenge(id self,
                                                 SEL command,
                                                 NSURLAuthenticationChallenge *challenge,
                                                 ICChallengeCompletion completion) {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] &&
        challenge.protectionSpace.serverTrust && completion) {
        NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        completion(NSURLSessionAuthChallengeUseCredential, credential);
        return YES;
    }
    return ICOriginalTrustKitHandleChallenge
        ? ICOriginalTrustKitHandleChallenge(self, command, challenge, completion)
        : NO;
}

static BOOL ICInstallMessageHook(Class targetClass, SEL selector, IMP replacement, IMP *original) {
    Method method = targetClass ? class_getInstanceMethod(targetClass, selector) : NULL;
    if (!method) {
        return NO;
    }
#if defined(IOSCAPTURE_DIRECT_INJECTION)
    IMP previous = method_setImplementation(method, replacement);
    if (original) {
        *original = previous;
    }
#else
    MSHookMessageEx(targetClass, selector, replacement, original);
#endif
    return YES;
}

static NSUInteger ICInstallObjectiveCHooks(void) {
    static BOOL afInstalled = NO;
    static BOOL trustKitEvaluateInstalled = NO;
    static BOOL trustKitChallengeInstalled = NO;
    NSUInteger count = 0;

    Class afSecurityPolicy = objc_getClass("AFSecurityPolicy");
    SEL afSelector = sel_registerName("evaluateServerTrust:forDomain:");
    if (!afInstalled && ICInstallMessageHook(afSecurityPolicy,
                                             afSelector,
                                             reinterpret_cast<IMP>(&ICReplacementAFEvaluate),
                                             reinterpret_cast<IMP *>(&ICOriginalAFEvaluate))) {
        afInstalled = YES;
        count++;
    }

    Class trustKit = objc_getClass("TSKPinningValidator");
    SEL evaluateSelector = sel_registerName("evaluateTrust:forHostname:");
    if (!trustKitEvaluateInstalled && ICInstallMessageHook(trustKit,
                                                           evaluateSelector,
                                                           reinterpret_cast<IMP>(&ICReplacementTrustKitEvaluate),
                                                           reinterpret_cast<IMP *>(&ICOriginalTrustKitEvaluate))) {
        trustKitEvaluateInstalled = YES;
        count++;
    }

    SEL challengeSelector = sel_registerName("handleChallenge:completionHandler:");
    if (!trustKitChallengeInstalled && ICInstallMessageHook(trustKit,
                                                            challengeSelector,
                                                            reinterpret_cast<IMP>(&ICReplacementTrustKitHandleChallenge),
                                                            reinterpret_cast<IMP *>(&ICOriginalTrustKitHandleChallenge))) {
        trustKitChallengeInstalled = YES;
        count++;
    }

    return count;
}

#pragma mark - Dynamically linked native TLS

typedef int (*ICBoringSSLVerifyCallback)(void *ssl, uint8_t *alert);
typedef void (*ICSSLSetCustomVerify)(void *ssl, int mode, ICBoringSSLVerifyCallback callback);

static ICSSLSetCustomVerify ICOriginalSSLSetCustomVerify = NULL;
static ICSSLSetCustomVerify ICOriginalSSLCTXSetCustomVerify = NULL;

static int ICBoringSSLAlwaysAllow(void *ssl, uint8_t *alert) {
    if (alert) {
        *alert = 0;
    }
    return 0; // ssl_verify_ok
}

static void ICReplacementSSLSetCustomVerify(void *ssl, int mode, ICBoringSSLVerifyCallback callback) {
    if (ICOriginalSSLSetCustomVerify) {
        ICOriginalSSLSetCustomVerify(ssl, mode, &ICBoringSSLAlwaysAllow);
    }
}

static void ICReplacementSSLCTXSetCustomVerify(void *sslContext,
                                               int mode,
                                               ICBoringSSLVerifyCallback callback) {
    if (ICOriginalSSLCTXSetCustomVerify) {
        ICOriginalSSLCTXSetCustomVerify(sslContext, mode, &ICBoringSSLAlwaysAllow);
    }
}

typedef int (*ICOpenSSLVerifyCallback)(int preverifyOK, void *storeContext);
typedef void (*ICSSLSetVerify)(void *ssl, int mode, ICOpenSSLVerifyCallback callback);

static ICSSLSetVerify ICOriginalSSLSetVerify = NULL;
static ICSSLSetVerify ICOriginalSSLCTXSetVerify = NULL;

static int ICOpenSSLAlwaysAllow(int preverifyOK, void *storeContext) {
    return 1;
}

static void ICReplacementSSLSetVerify(void *ssl, int mode, ICOpenSSLVerifyCallback callback) {
    if (ICOriginalSSLSetVerify) {
        ICOriginalSSLSetVerify(ssl, mode, &ICOpenSSLAlwaysAllow);
    }
}

static void ICReplacementSSLCTXSetVerify(void *sslContext, int mode, ICOpenSSLVerifyCallback callback) {
    if (ICOriginalSSLCTXSetVerify) {
        ICOriginalSSLCTXSetVerify(sslContext, mode, &ICOpenSSLAlwaysAllow);
    }
}

static long (*ICOriginalSSLGetVerifyResult)(const void *ssl) = NULL;
static long ICReplacementSSLGetVerifyResult(const void *ssl) {
    return 0; // X509_V_OK
}

static NSUInteger ICInstallNativeTLSHooks(void) {
    NSUInteger count = 0;

    if (ICInstallFunctionHook("SSL_set_custom_verify",
                              reinterpret_cast<void *>(&ICReplacementSSLSetCustomVerify),
                              reinterpret_cast<void **>(&ICOriginalSSLSetCustomVerify))) {
        count++;
    }

    if (ICInstallFunctionHook("SSL_CTX_set_custom_verify",
                              reinterpret_cast<void *>(&ICReplacementSSLCTXSetCustomVerify),
                              reinterpret_cast<void **>(&ICOriginalSSLCTXSetCustomVerify))) {
        count++;
    }

    if (ICInstallFunctionHook("SSL_set_verify",
                              reinterpret_cast<void *>(&ICReplacementSSLSetVerify),
                              reinterpret_cast<void **>(&ICOriginalSSLSetVerify))) {
        count++;
    }

    if (ICInstallFunctionHook("SSL_CTX_set_verify",
                              reinterpret_cast<void *>(&ICReplacementSSLCTXSetVerify),
                              reinterpret_cast<void **>(&ICOriginalSSLCTXSetVerify))) {
        count++;
    }

    if (ICInstallFunctionHook("SSL_get_verify_result",
                              reinterpret_cast<void *>(&ICReplacementSSLGetVerifyResult),
                              reinterpret_cast<void **>(&ICOriginalSSLGetVerifyResult))) {
        count++;
    }

    return count;
}

void ICInstallTLSHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier ?: @"unknown";
        NSUInteger installed = 0;

#if defined(IOSCAPTURE_DIRECT_INJECTION)
        BOOL tlsBypassEnabled = YES;
        BOOL nativeTLSBypassEnabled = YES;
#else
        BOOL tlsBypassEnabled = ICBoolPreference(ICTLSBypassEnabledKey, YES);
        BOOL nativeTLSBypassEnabled = ICBoolPreference(ICNativeTLSBypassEnabledKey, NO);
#endif

        if (tlsBypassEnabled) {
            installed += ICInstallSecurityHooks();
            installed += ICInstallObjectiveCHooks();
        }

        if (nativeTLSBypassEnabled) {
            installed += ICInstallNativeTLSHooks();
        }

        ICLog(@"active in %@, installed %lu hook groups", bundleIdentifier, (unsigned long)installed);

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            NSUInteger lateHooks = ICInstallObjectiveCHooks();
            if (lateHooks > 0) {
                ICLog(@"installed %lu late Objective-C hooks", (unsigned long)lateHooks);
            }
        });
    });
}
