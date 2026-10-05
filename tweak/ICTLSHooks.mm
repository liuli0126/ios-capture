#import "ICTLSHooks.h"

#import "ICPreferences.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Security/SecProtocolOptions.h>
#import <dlfcn.h>
#import <errno.h>
#import <mach-o/dyld.h>
#import <netinet/in.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdatomic.h>
#import <string.h>
#import <sys/socket.h>
#if __has_feature(ptrauth_calls)
#import <ptrauth.h>
#endif
#if !defined(IOSCAPTURE_DIRECT_INJECTION)
#import <substrate.h>
#endif

static NSUInteger ICInstalledHookTotal = 0;
static dispatch_queue_t ICHookQueue = NULL;
static _Atomic bool ICHookScanQueued = false;
static BOOL ICTLSHooksEnabled = YES;
static BOOL ICNativeTLSHooksEnabled = YES;
static BOOL ICHTTP3FallbackEnabled = YES;

typedef NS_ENUM(NSUInteger, ICHookCategory) {
    ICHookCategorySystem = 0,
    ICHookCategoryURLSession,
    ICHookCategoryTTNet,
    ICHookCategoryNativeTLS,
    ICHookCategoryQUIC,
    ICHookCategoryCount,
};

static _Atomic unsigned long ICInstalledByCategory[ICHookCategoryCount];
static _Atomic unsigned long ICHitsByCategory[ICHookCategoryCount];
static _Atomic unsigned long ICTTTaskClassesSeen = 0;

static void ICInstallAvailableHooks(void);

static void ICRecordCategory(ICHookCategory category, NSUInteger count) {
    if (count > 0) {
        atomic_fetch_add_explicit(&ICInstalledByCategory[category],
                                  (unsigned long)count,
                                  memory_order_relaxed);
    }
}

static void ICRecordHit(ICHookCategory category) {
    atomic_fetch_add_explicit(&ICHitsByCategory[category], 1, memory_order_relaxed);
}

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

    static void *frameworkHandles[3] = {NULL, NULL, NULL};
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        frameworkHandles[0] = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
        frameworkHandles[1] = dlopen("/System/Library/Frameworks/Network.framework/Network", RTLD_LAZY);
        frameworkHandles[2] = dlopen("/usr/lib/libboringssl.dylib", RTLD_LAZY);
    });
    for (NSUInteger index = 0; index < 3; index++) {
        if (frameworkHandles[index]) {
            symbol = dlsym(frameworkHandles[index], name);
            if (symbol) {
                return symbol;
            }
        }
    }
    return NULL;
}

static void *ICResolveNativeTLSSymbol(const char *name) {
    const uint32_t imageCount = _dyld_image_count();
    for (uint32_t index = 0; index < imageCount; index++) {
        const char *imageName = _dyld_get_image_name(index);
        if (!imageName) {
            continue;
        }
        const char *lowerPriorityMarkers[] = {
            "boringssl", "cronet", "TTNetwork", "libvcn", "ByteDance", NULL,
        };
        BOOL relevant = NO;
        for (NSUInteger marker = 0; lowerPriorityMarkers[marker] != NULL; marker++) {
            if (strcasestr(imageName, lowerPriorityMarkers[marker])) {
                relevant = YES;
                break;
            }
        }
        if (!relevant) {
            continue;
        }
        void *handle = dlopen(imageName, RTLD_LAZY);
        void *symbol = handle ? dlsym(handle, name) : NULL;
        if (symbol) {
            ICLog(@"resolved %s in %s", name, imageName);
            return symbol;
        }
    }
    return ICResolveSymbol(name);
}

#if defined(IOSCAPTURE_DIRECT_INJECTION)
typedef void (*ICMSHookFunction)(void *symbol, void *replacement, void **original);

static ICMSHookFunction ICRuntimeHookFunction = NULL;

static ICMSHookFunction ICResolveRuntimeHookFunction(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        ICRuntimeHookFunction = reinterpret_cast<ICMSHookFunction>(dlsym(RTLD_DEFAULT, "MSHookFunction"));
        if (ICRuntimeHookFunction) {
            return;
        }

        const char *candidatePaths[] = {
            "/var/jb/usr/lib/libellekit.dylib",
            "/usr/lib/libellekit.dylib",
            "/var/jb/usr/lib/libsubstrate.dylib",
            "/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
            "/usr/lib/libsubstrate.dylib",
            "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
            NULL,
        };
        for (NSUInteger index = 0; candidatePaths[index] != NULL; index++) {
            void *handle = dlopen(candidatePaths[index], RTLD_LAZY | RTLD_GLOBAL);
            if (!handle) {
                continue;
            }
            ICRuntimeHookFunction = reinterpret_cast<ICMSHookFunction>(dlsym(handle, "MSHookFunction"));
            if (ICRuntimeHookFunction) {
                ICLog(@"loaded Hook runtime from %s", candidatePaths[index]);
                break;
            }
        }
    });
    return ICRuntimeHookFunction;
}
#endif

static BOOL ICInstallFunctionHook(const char *name, void *replacement, void **original) {
    if (original && *original) {
        return NO;
    }
#if defined(IOSCAPTURE_DIRECT_INJECTION)
    void *symbol = ICResolveSymbol(name);
    ICMSHookFunction hookFunction = ICResolveRuntimeHookFunction();
    if (!symbol || !hookFunction) {
        return NO;
    }
    hookFunction(symbol, replacement, original);
    return original ? *original != NULL : YES;
#else
    void *symbol = ICResolveSymbol(name);
    if (!symbol) {
        return NO;
    }
    MSHookFunction(symbol, replacement, original);
    return original ? *original != NULL : YES;
#endif
}

static BOOL ICInstallNativeFunctionHook(const char *name, void *replacement, void **original) {
    if (original && *original) {
        return NO;
    }
    void *symbol = ICResolveNativeTLSSymbol(name);
#if __has_feature(ptrauth_calls)
    if (symbol) {
        symbol = ptrauth_strip(symbol, ptrauth_key_function_pointer);
    }
#endif
#if defined(IOSCAPTURE_DIRECT_INJECTION)
    ICMSHookFunction hookFunction = ICResolveRuntimeHookFunction();
    if (!symbol || !hookFunction) {
        return NO;
    }
    hookFunction(symbol, replacement, original);
#else
    if (!symbol) {
        return NO;
    }
    MSHookFunction(symbol, replacement, original);
#endif
    return original ? *original != NULL : YES;
}

NSUInteger ICInstalledTLSHookCount(void) {
    @synchronized (NSProcessInfo.processInfo) {
        return ICInstalledHookTotal;
    }
}

BOOL ICHookRuntimeAvailable(void) {
#if defined(IOSCAPTURE_DIRECT_INJECTION)
    return ICResolveRuntimeHookFunction() != NULL;
#else
    return YES;
#endif
}

NSString *ICCopyTLSHookStatusSummary(void) {
    unsigned long installed[ICHookCategoryCount] = {0};
    unsigned long hits[ICHookCategoryCount] = {0};
    for (NSUInteger index = 0; index < ICHookCategoryCount; index++) {
        installed[index] = atomic_load_explicit(&ICInstalledByCategory[index], memory_order_relaxed);
        hits[index] = atomic_load_explicit(&ICHitsByCategory[index], memory_order_relaxed);
    }

    BOOL hasTTImage = NO;
    BOOL hasCronetImage = NO;
    BOOL hasVCNImage = NO;
    const uint32_t imageCount = _dyld_image_count();
    for (uint32_t index = 0; index < imageCount; index++) {
        const char *imageName = _dyld_get_image_name(index);
        if (!imageName) {
            continue;
        }
        hasTTImage |= strcasestr(imageName, "TTNetwork") != NULL ||
                      strcasestr(imageName, "ByteDance") != NULL;
        hasCronetImage |= strcasestr(imageName, "cronet") != NULL ||
                          strcasestr(imageName, "boringssl") != NULL;
        hasVCNImage |= strcasestr(imageName, "libvcn") != NULL;
    }

    return [NSString stringWithFormat:
        @"iOS Capture 0.1.6  install/hit\nS%lu/%lu U%lu/%lu TT%lu/%lu N%lu/%lu Q%lu/%lu\nObj%lu Img T%d C%d V%d",
        installed[ICHookCategorySystem], hits[ICHookCategorySystem],
        installed[ICHookCategoryURLSession], hits[ICHookCategoryURLSession],
        installed[ICHookCategoryTTNet], hits[ICHookCategoryTTNet],
        installed[ICHookCategoryNativeTLS], hits[ICHookCategoryNativeTLS],
        installed[ICHookCategoryQUIC], hits[ICHookCategoryQUIC],
        atomic_load_explicit(&ICTTTaskClassesSeen, memory_order_relaxed),
        hasTTImage ? 1 : 0,
        hasCronetImage ? 1 : 0,
        hasVCNImage ? 1 : 0];
}

#pragma mark - Security.framework

static OSStatus (*ICOriginalSecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result) = NULL;
static OSStatus ICReplacementSecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    ICRecordHit(ICHookCategorySystem);
    if (result) {
        *result = kSecTrustResultProceed;
    }
    return errSecSuccess;
}

static Boolean (*ICOriginalSecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef *error) = NULL;
static Boolean ICReplacementSecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    ICRecordHit(ICHookCategorySystem);
    if (error) {
        *error = NULL;
    }
    return true;
}

static OSStatus (*ICOriginalSecTrustEvaluateAsync)(SecTrustRef trust,
                                                    dispatch_queue_t queue,
                                                    SecTrustCallback callback) = NULL;
static OSStatus ICReplacementSecTrustEvaluateAsync(SecTrustRef trust,
                                                    dispatch_queue_t queue,
                                                    SecTrustCallback callback) {
    ICRecordHit(ICHookCategorySystem);
    if (callback) {
        callback(trust, kSecTrustResultProceed);
    }
    return errSecSuccess;
}

static OSStatus (*ICOriginalSecTrustEvaluateAsyncWithError)(SecTrustRef trust,
                                                             dispatch_queue_t queue,
                                                             SecTrustWithErrorCallback callback) = NULL;
static OSStatus ICReplacementSecTrustEvaluateAsyncWithError(SecTrustRef trust,
                                                             dispatch_queue_t queue,
                                                             SecTrustWithErrorCallback callback) {
    ICRecordHit(ICHookCategorySystem);
    if (callback) {
        callback(trust, true, NULL);
    }
    return errSecSuccess;
}

static OSStatus (*ICOriginalSecTrustEvaluateFastAsync)(SecTrustRef trust,
                                                        dispatch_queue_t queue,
                                                        SecTrustCallback callback) = NULL;
static OSStatus ICReplacementSecTrustEvaluateFastAsync(SecTrustRef trust,
                                                        dispatch_queue_t queue,
                                                        SecTrustCallback callback) {
    ICRecordHit(ICHookCategorySystem);
    if (callback) {
        callback(trust, kSecTrustResultProceed);
    }
    return errSecSuccess;
}

static OSStatus (*ICOriginalSecTrustGetTrustResult)(SecTrustRef trust, SecTrustResultType *result) = NULL;
static OSStatus ICReplacementSecTrustGetTrustResult(SecTrustRef trust, SecTrustResultType *result) {
    ICRecordHit(ICHookCategorySystem);
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

    if (ICInstallFunctionHook("SecTrustEvaluateAsync",
                              reinterpret_cast<void *>(&ICReplacementSecTrustEvaluateAsync),
                              reinterpret_cast<void **>(&ICOriginalSecTrustEvaluateAsync))) {
        count++;
    }

    if (ICInstallFunctionHook("SecTrustEvaluateAsyncWithError",
                              reinterpret_cast<void *>(&ICReplacementSecTrustEvaluateAsyncWithError),
                              reinterpret_cast<void **>(&ICOriginalSecTrustEvaluateAsyncWithError))) {
        count++;
    }

    if (ICInstallFunctionHook("SecTrustEvaluateFastAsync",
                              reinterpret_cast<void *>(&ICReplacementSecTrustEvaluateFastAsync),
                              reinterpret_cast<void **>(&ICOriginalSecTrustEvaluateFastAsync))) {
        count++;
    }

    if (ICInstallFunctionHook("SecTrustGetTrustResult",
                              reinterpret_cast<void *>(&ICReplacementSecTrustGetTrustResult),
                              reinterpret_cast<void **>(&ICOriginalSecTrustGetTrustResult))) {
        count++;
    }

    return count;
}

#pragma mark - Network.framework

static void (*ICOriginalProtocolSetVerifyBlock)(sec_protocol_options_t options,
                                                 sec_protocol_verify_t verifyBlock,
                                                 dispatch_queue_t verifyQueue) = NULL;
static sec_protocol_verify_t ICAllowProtocolVerifyBlock = nil;

static void ICReplacementProtocolSetVerifyBlock(sec_protocol_options_t options,
                                                 sec_protocol_verify_t verifyBlock,
                                                 dispatch_queue_t verifyQueue) {
    ICRecordHit(ICHookCategorySystem);
    if (ICOriginalProtocolSetVerifyBlock && ICAllowProtocolVerifyBlock) {
        ICOriginalProtocolSetVerifyBlock(options, ICAllowProtocolVerifyBlock, verifyQueue);
    }
}

static NSUInteger ICInstallNetworkFrameworkHooks(void) {
    if (!ICAllowProtocolVerifyBlock) {
        ICAllowProtocolVerifyBlock = [^(sec_protocol_metadata_t metadata,
                                        sec_trust_t trust,
                                        sec_protocol_verify_complete_t complete) {
            if (complete) {
                complete(true);
            }
        } copy];
    }
    return ICInstallFunctionHook("sec_protocol_options_set_verify_block",
                                 reinterpret_cast<void *>(&ICReplacementProtocolSetVerifyBlock),
                                 reinterpret_cast<void **>(&ICOriginalProtocolSetVerifyBlock)) ? 1 : 0;
}

#pragma mark - Objective-C trust paths

typedef void (^ICChallengeCompletion)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential *credential);

static BOOL ICClassDefinesSelector(Class targetClass, SEL selector);

static BOOL ICInstallMessageHook(Class targetClass, SEL selector, IMP replacement, IMP *original) {
    if (!targetClass || (original && *original)) {
        return NO;
    }
    Method method = class_getInstanceMethod(targetClass, selector);
    if (!method || method_getImplementation(method) == replacement) {
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
    return original ? *original != NULL : YES;
}

static BOOL ICInstallMessageReplacement(Class targetClass, SEL selector, IMP replacement) {
    Method method = targetClass ? class_getInstanceMethod(targetClass, selector) : NULL;
    if (!method || !ICClassDefinesSelector(targetClass, selector) ||
        method_getImplementation(method) == replacement) {
        return NO;
    }
    method_setImplementation(method, replacement);
    return YES;
}

static BOOL ICClassDefinesSelector(Class targetClass, SEL selector) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(targetClass, &count);
    BOOL found = NO;
    for (unsigned int index = 0; index < count; index++) {
        if (method_getName(methods[index]) == selector) {
            found = YES;
            break;
        }
    }
    free(methods);
    return found;
}

#pragma mark AFNetworking and TrustKit

static BOOL (*ICOriginalAFEvaluate)(id, SEL, SecTrustRef, NSString *) = NULL;
static void (*ICOriginalAFSetPinningMode)(id, SEL, NSUInteger) = NULL;
static void (*ICOriginalAFSetAllowInvalid)(id, SEL, BOOL) = NULL;
static id (*ICOriginalAFPolicyWithMode)(id, SEL, NSUInteger) = NULL;
static id (*ICOriginalAFPolicyWithModeAndCertificates)(id, SEL, NSUInteger, id) = NULL;

static BOOL ICReplacementAFEvaluate(id self, SEL command, SecTrustRef trust, NSString *domain) {
    ICRecordHit(ICHookCategoryURLSession);
    return YES;
}

static void ICReplacementAFSetPinningMode(id self, SEL command, NSUInteger mode) {
    ICRecordHit(ICHookCategoryURLSession);
    if (ICOriginalAFSetPinningMode) {
        ICOriginalAFSetPinningMode(self, command, 0);
    }
}

static void ICReplacementAFSetAllowInvalid(id self, SEL command, BOOL allowed) {
    ICRecordHit(ICHookCategoryURLSession);
    if (ICOriginalAFSetAllowInvalid) {
        ICOriginalAFSetAllowInvalid(self, command, YES);
    }
}

static id ICReplacementAFPolicyWithMode(id self, SEL command, NSUInteger mode) {
    ICRecordHit(ICHookCategoryURLSession);
    return ICOriginalAFPolicyWithMode ? ICOriginalAFPolicyWithMode(self, command, 0) : nil;
}

static id ICReplacementAFPolicyWithModeAndCertificates(id self,
                                                        SEL command,
                                                        NSUInteger mode,
                                                        id certificates) {
    ICRecordHit(ICHookCategoryURLSession);
    return ICOriginalAFPolicyWithModeAndCertificates
        ? ICOriginalAFPolicyWithModeAndCertificates(self, command, 0, certificates)
        : nil;
}

static NSInteger (*ICOriginalTrustKitEvaluate)(id, SEL, SecTrustRef, NSString *) = NULL;
static NSInteger (*ICOriginalTrustKitClassEvaluate)(id, SEL, SecTrustRef, NSString *) = NULL;
static BOOL (*ICOriginalTrustKitHandleChallenge)(id, SEL, NSURLAuthenticationChallenge *, ICChallengeCompletion) = NULL;

static NSInteger ICReplacementTrustKitEvaluate(id self, SEL command, SecTrustRef trust, NSString *hostname) {
    ICRecordHit(ICHookCategoryURLSession);
    return 0;
}

static BOOL ICReplacementTrustKitHandleChallenge(id self,
                                                 SEL command,
                                                 NSURLAuthenticationChallenge *challenge,
                                                 ICChallengeCompletion completion) {
    ICRecordHit(ICHookCategoryURLSession);
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] &&
        challenge.protectionSpace.serverTrust && completion) {
        completion(NSURLSessionAuthChallengeUseCredential,
                   [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
        return YES;
    }
    return ICOriginalTrustKitHandleChallenge
        ? ICOriginalTrustKitHandleChallenge(self, command, challenge, completion)
        : NO;
}

#pragma mark NSURLSession delegates

static NSMapTable *ICSessionChallengeOriginals = nil;
static NSMapTable *ICTaskChallengeOriginals = nil;

static IMP ICLookupDelegateOriginal(NSMapTable *table, id instance) {
    @synchronized (table) {
        for (Class cursor = object_getClass(instance); cursor; cursor = class_getSuperclass(cursor)) {
            NSValue *value = [table objectForKey:cursor];
            if (value) {
                IMP original = NULL;
                [value getValue:&original];
                return original;
            }
        }
    }
    return NULL;
}

static BOOL ICAllowServerTrustChallenge(NSURLAuthenticationChallenge *challenge,
                                        ICChallengeCompletion completion) {
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] ||
        !challenge.protectionSpace.serverTrust || !completion) {
        return NO;
    }
    completion(NSURLSessionAuthChallengeUseCredential,
               [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
    return YES;
}

static void ICReplacementSessionChallenge(id self,
                                          SEL command,
                                          NSURLSession *session,
                                          NSURLAuthenticationChallenge *challenge,
                                          ICChallengeCompletion completion) {
    ICRecordHit(ICHookCategoryURLSession);
    if (ICAllowServerTrustChallenge(challenge, completion)) {
        return;
    }
    IMP original = ICLookupDelegateOriginal(ICSessionChallengeOriginals, self);
    if (original) {
        reinterpret_cast<void (*)(id, SEL, NSURLSession *, NSURLAuthenticationChallenge *, ICChallengeCompletion)>(original)
            (self, command, session, challenge, completion);
    } else if (completion) {
        completion(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

static void ICReplacementTaskChallenge(id self,
                                       SEL command,
                                       NSURLSession *session,
                                       NSURLSessionTask *task,
                                       NSURLAuthenticationChallenge *challenge,
                                       ICChallengeCompletion completion) {
    ICRecordHit(ICHookCategoryURLSession);
    if (ICAllowServerTrustChallenge(challenge, completion)) {
        return;
    }
    IMP original = ICLookupDelegateOriginal(ICTaskChallengeOriginals, self);
    if (original) {
        reinterpret_cast<void (*)(id, SEL, NSURLSession *, NSURLSessionTask *, NSURLAuthenticationChallenge *, ICChallengeCompletion)>(original)
            (self, command, session, task, challenge, completion);
    } else if (completion) {
        completion(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

static BOOL ICInstallDelegateHook(Class targetClass,
                                  SEL selector,
                                  IMP replacement,
                                  NSMapTable *originals) {
    if (!ICClassDefinesSelector(targetClass, selector)) {
        return NO;
    }
    @synchronized (originals) {
        if ([originals objectForKey:targetClass]) {
            return NO;
        }
        IMP original = NULL;
        if (!ICInstallMessageHook(targetClass, selector, replacement, &original) || !original) {
            return NO;
        }
        [originals setObject:[NSValue value:&original withObjCType:@encode(IMP)]
                       forKey:targetClass];
        return YES;
    }
}

static NSUInteger ICInstallURLSessionDelegateHooks(void) {
    if (!ICSessionChallengeOriginals) {
        ICSessionChallengeOriginals = [NSMapTable strongToStrongObjectsMapTable];
        ICTaskChallengeOriginals = [NSMapTable strongToStrongObjectsMapTable];
    }
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) {
        return 0;
    }
    Class *classes = reinterpret_cast<Class *>(calloc((size_t)count, sizeof(Class)));
    count = objc_getClassList(classes, count);
    SEL sessionSelector = sel_registerName("URLSession:didReceiveChallenge:completionHandler:");
    SEL taskSelector = sel_registerName("URLSession:task:didReceiveChallenge:completionHandler:");
    NSUInteger installed = 0;
    for (int index = 0; index < count; index++) {
        installed += ICInstallDelegateHook(classes[index], sessionSelector,
                                           reinterpret_cast<IMP>(&ICReplacementSessionChallenge),
                                           ICSessionChallengeOriginals) ? 1 : 0;
        installed += ICInstallDelegateHook(classes[index], taskSelector,
                                           reinterpret_cast<IMP>(&ICReplacementTaskChallenge),
                                           ICTaskChallengeOriginals) ? 1 : 0;
    }
    free(classes);
    return installed;
}

#pragma mark TTNet and QUIC

static BOOL (*ICOriginalTTGetSkipCertificateError)(id, SEL) = NULL;
static void (*ICOriginalTTSetSkipCertificateError)(id, SEL, BOOL) = NULL;
static void (*ICOriginalTTResume)(id, SEL) = NULL;

static BOOL ICReplacementTTGetSkipCertificateError(id self, SEL command) {
    ICRecordHit(ICHookCategoryTTNet);
    return YES;
}

static void ICReplacementTTSetSkipCertificateError(id self, SEL command, BOOL enabled) {
    ICRecordHit(ICHookCategoryTTNet);
    if (ICOriginalTTSetSkipCertificateError) {
        ICOriginalTTSetSkipCertificateError(self, command, YES);
    }
}

static void ICReplacementTTResume(id self, SEL command) {
    ICRecordHit(ICHookCategoryTTNet);
    SEL setter = sel_registerName("setSkipSSLCertificateError:");
    if ([self respondsToSelector:setter]) {
        reinterpret_cast<void (*)(id, SEL, BOOL)>(objc_msgSend)(self, setter, YES);
    }
    if (ICOriginalTTResume) {
        ICOriginalTTResume(self, command);
    }
}

static id ICReplacementNoCertificates(id self, SEL command) {
    ICRecordHit(ICHookCategoryTTNet);
    return nil;
}

static void ICReplacementClearCertificates(id self, SEL command, id certificates) {
    ICRecordHit(ICHookCategoryTTNet);
}

static BOOL ICReplacementQuicDisabled(id self, SEL command) {
    ICRecordHit(ICHookCategoryQUIC);
    return NO;
}

static void ICReplacementDisableQuicSetter(id self, SEL command, BOOL enabled) {
    ICRecordHit(ICHookCategoryQUIC);
}

static NSUInteger ICInstallTTNetHooks(void) {
    NSUInteger count = 0;
    Class taskClass = objc_getClass("TTHttpTask");
    if (ICInstallMessageHook(taskClass,
                             sel_registerName("skipSSLCertificateError"),
                             reinterpret_cast<IMP>(&ICReplacementTTGetSkipCertificateError),
                             reinterpret_cast<IMP *>(&ICOriginalTTGetSkipCertificateError))) {
        count++;
    }
    if (ICInstallMessageHook(taskClass,
                             sel_registerName("setSkipSSLCertificateError:"),
                             reinterpret_cast<IMP>(&ICReplacementTTSetSkipCertificateError),
                             reinterpret_cast<IMP *>(&ICOriginalTTSetSkipCertificateError))) {
        count++;
    }
    if (ICInstallMessageHook(taskClass,
                             sel_registerName("resume"),
                             reinterpret_cast<IMP>(&ICReplacementTTResume),
                             reinterpret_cast<IMP *>(&ICOriginalTTResume))) {
        count++;
    }

    int classCount = objc_getClassList(NULL, 0);
    NSUInteger matchingTaskClasses = 0;
    if (classCount > 0) {
        Class *classes = reinterpret_cast<Class *>(calloc((size_t)classCount, sizeof(Class)));
        classCount = objc_getClassList(classes, classCount);
        SEL skipSelector = sel_registerName("skipSSLCertificateError");
        for (int index = 0; index < classCount; index++) {
            if (!ICClassDefinesSelector(classes[index], skipSelector)) {
                continue;
            }
            matchingTaskClasses++;
            count += ICInstallMessageReplacement(classes[index], skipSelector,
                                                  reinterpret_cast<IMP>(&ICReplacementTTGetSkipCertificateError)) ? 1 : 0;
        }
        free(classes);
    }
    atomic_store_explicit(&ICTTTaskClassesSeen,
                          (unsigned long)matchingTaskClasses,
                          memory_order_relaxed);

    const char *managerClasses[] = {"TTNetworkManagerChromium", "TTNetworkManager", NULL};
    const char *certificateGetters[] = {"ServerCertificate", "serverCertificate", NULL};
    const char *certificateSetters[] = {"setServerCertificate:", NULL};
    for (NSUInteger classIndex = 0; managerClasses[classIndex]; classIndex++) {
        Class manager = objc_getClass(managerClasses[classIndex]);
        for (NSUInteger selectorIndex = 0; certificateGetters[selectorIndex]; selectorIndex++) {
            SEL selector = sel_registerName(certificateGetters[selectorIndex]);
            count += ICInstallMessageReplacement(manager, selector,
                                                  reinterpret_cast<IMP>(&ICReplacementNoCertificates)) ? 1 : 0;
            count += ICInstallMessageReplacement(object_getClass(manager), selector,
                                                  reinterpret_cast<IMP>(&ICReplacementNoCertificates)) ? 1 : 0;
        }
        for (NSUInteger selectorIndex = 0; certificateSetters[selectorIndex]; selectorIndex++) {
            SEL selector = sel_registerName(certificateSetters[selectorIndex]);
            count += ICInstallMessageReplacement(manager, selector,
                                                  reinterpret_cast<IMP>(&ICReplacementClearCertificates)) ? 1 : 0;
            count += ICInstallMessageReplacement(object_getClass(manager), selector,
                                                  reinterpret_cast<IMP>(&ICReplacementClearCertificates)) ? 1 : 0;
        }
    }
    return count;
}

static NSUInteger ICInstallQuicConfigurationHooks(void) {
    NSUInteger count = 0;
    const char *classNames[] = {"BDQuicConfig", "TTQuicConfig", "TTQUICConfig", NULL};
    const char *getterNames[] = {"enable", "enabled", "isEnabled", NULL};
    const char *setterNames[] = {"setEnable:", "setEnabled:", NULL};
    for (NSUInteger classIndex = 0; classNames[classIndex]; classIndex++) {
        Class targetClass = objc_getClass(classNames[classIndex]);
        for (NSUInteger selectorIndex = 0; getterNames[selectorIndex]; selectorIndex++) {
            count += ICInstallMessageReplacement(targetClass,
                                                  sel_registerName(getterNames[selectorIndex]),
                                                  reinterpret_cast<IMP>(&ICReplacementQuicDisabled)) ? 1 : 0;
        }
        for (NSUInteger selectorIndex = 0; setterNames[selectorIndex]; selectorIndex++) {
            count += ICInstallMessageReplacement(targetClass,
                                                  sel_registerName(setterNames[selectorIndex]),
                                                  reinterpret_cast<IMP>(&ICReplacementDisableQuicSetter)) ? 1 : 0;
        }
    }
    return count;
}

static NSUInteger ICInstallObjectiveCHooks(void) {
    NSUInteger count = 0;

    Class afSecurityPolicy = objc_getClass("AFSecurityPolicy");
    count += ICInstallMessageHook(afSecurityPolicy,
                                  sel_registerName("evaluateServerTrust:forDomain:"),
                                  reinterpret_cast<IMP>(&ICReplacementAFEvaluate),
                                  reinterpret_cast<IMP *>(&ICOriginalAFEvaluate)) ? 1 : 0;
    count += ICInstallMessageHook(afSecurityPolicy,
                                  sel_registerName("setSSLPinningMode:"),
                                  reinterpret_cast<IMP>(&ICReplacementAFSetPinningMode),
                                  reinterpret_cast<IMP *>(&ICOriginalAFSetPinningMode)) ? 1 : 0;
    count += ICInstallMessageHook(afSecurityPolicy,
                                  sel_registerName("setAllowInvalidCertificates:"),
                                  reinterpret_cast<IMP>(&ICReplacementAFSetAllowInvalid),
                                  reinterpret_cast<IMP *>(&ICOriginalAFSetAllowInvalid)) ? 1 : 0;
    Class afMetaClass = object_getClass(afSecurityPolicy);
    count += ICInstallMessageHook(afMetaClass,
                                  sel_registerName("policyWithPinningMode:"),
                                  reinterpret_cast<IMP>(&ICReplacementAFPolicyWithMode),
                                  reinterpret_cast<IMP *>(&ICOriginalAFPolicyWithMode)) ? 1 : 0;
    count += ICInstallMessageHook(afMetaClass,
                                  sel_registerName("policyWithPinningMode:withPinnedCertificates:"),
                                  reinterpret_cast<IMP>(&ICReplacementAFPolicyWithModeAndCertificates),
                                  reinterpret_cast<IMP *>(&ICOriginalAFPolicyWithModeAndCertificates)) ? 1 : 0;

    Class trustKit = objc_getClass("TSKPinningValidator");
    SEL trustKitSelector = sel_registerName("evaluateTrust:forHostname:");
    count += ICInstallMessageHook(trustKit, trustKitSelector,
                                  reinterpret_cast<IMP>(&ICReplacementTrustKitEvaluate),
                                  reinterpret_cast<IMP *>(&ICOriginalTrustKitEvaluate)) ? 1 : 0;
    count += ICInstallMessageHook(object_getClass(trustKit), trustKitSelector,
                                  reinterpret_cast<IMP>(&ICReplacementTrustKitEvaluate),
                                  reinterpret_cast<IMP *>(&ICOriginalTrustKitClassEvaluate)) ? 1 : 0;
    count += ICInstallMessageHook(trustKit,
                                  sel_registerName("handleChallenge:completionHandler:"),
                                  reinterpret_cast<IMP>(&ICReplacementTrustKitHandleChallenge),
                                  reinterpret_cast<IMP *>(&ICOriginalTrustKitHandleChallenge)) ? 1 : 0;

    count += ICInstallURLSessionDelegateHooks();
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
    ICRecordHit(ICHookCategoryNativeTLS);
    if (ICOriginalSSLSetCustomVerify) {
        ICOriginalSSLSetCustomVerify(ssl, 0, &ICBoringSSLAlwaysAllow);
    }
}

static void ICReplacementSSLCTXSetCustomVerify(void *sslContext,
                                               int mode,
                                               ICBoringSSLVerifyCallback callback) {
    ICRecordHit(ICHookCategoryNativeTLS);
    if (ICOriginalSSLCTXSetCustomVerify) {
        ICOriginalSSLCTXSetCustomVerify(sslContext, 0, &ICBoringSSLAlwaysAllow);
    }
}

#if !__has_feature(ptrauth_calls)
typedef int (*ICOpenSSLVerifyCallback)(int preverifyOK, void *storeContext);
typedef void (*ICSSLSetVerify)(void *ssl, int mode, ICOpenSSLVerifyCallback callback);

static ICSSLSetVerify ICOriginalSSLSetVerify = NULL;
static ICSSLSetVerify ICOriginalSSLCTXSetVerify = NULL;

static int ICOpenSSLAlwaysAllow(int preverifyOK, void *storeContext) {
    return 1;
}

static void ICReplacementSSLSetVerify(void *ssl, int mode, ICOpenSSLVerifyCallback callback) {
    ICRecordHit(ICHookCategoryNativeTLS);
    if (ICOriginalSSLSetVerify) {
        ICOriginalSSLSetVerify(ssl, mode, &ICOpenSSLAlwaysAllow);
    }
}

static void ICReplacementSSLCTXSetVerify(void *sslContext, int mode, ICOpenSSLVerifyCallback callback) {
    ICRecordHit(ICHookCategoryNativeTLS);
    if (ICOriginalSSLCTXSetVerify) {
        ICOriginalSSLCTXSetVerify(sslContext, mode, &ICOpenSSLAlwaysAllow);
    }
}
#endif

static long (*ICOriginalSSLGetVerifyResult)(const void *ssl) = NULL;
static long ICReplacementSSLGetVerifyResult(const void *ssl) {
    ICRecordHit(ICHookCategoryNativeTLS);
    return 0; // X509_V_OK
}

static int (*ICOriginalX509VerifyCert)(void *storeContext) = NULL;
static int ICReplacementX509VerifyCert(void *storeContext) {
    ICRecordHit(ICHookCategoryNativeTLS);
    return 1;
}

static const char *(*ICOriginalSSLGetPSKIdentity)(const void *ssl) = NULL;
static const char *ICReplacementSSLGetPSKIdentity(const void *ssl) {
    ICRecordHit(ICHookCategoryNativeTLS);
    return "ioscapture";
}

static NSUInteger ICInstallNativeTLSHooks(void) {
    NSUInteger count = 0;

    if (ICInstallNativeFunctionHook("SSL_set_custom_verify",
                                    reinterpret_cast<void *>(&ICReplacementSSLSetCustomVerify),
                                    reinterpret_cast<void **>(&ICOriginalSSLSetCustomVerify))) {
        count++;
    }

    if (ICInstallNativeFunctionHook("SSL_CTX_set_custom_verify",
                                    reinterpret_cast<void *>(&ICReplacementSSLCTXSetCustomVerify),
                                    reinterpret_cast<void **>(&ICOriginalSSLCTXSetCustomVerify))) {
        count++;
    }

#if !__has_feature(ptrauth_calls)
    if (ICInstallNativeFunctionHook("SSL_set_verify",
                                    reinterpret_cast<void *>(&ICReplacementSSLSetVerify),
                                    reinterpret_cast<void **>(&ICOriginalSSLSetVerify))) {
        count++;
    }

    if (ICInstallNativeFunctionHook("SSL_CTX_set_verify",
                                    reinterpret_cast<void *>(&ICReplacementSSLCTXSetVerify),
                                    reinterpret_cast<void **>(&ICOriginalSSLCTXSetVerify))) {
        count++;
    }
#endif

    if (ICInstallNativeFunctionHook("SSL_get_verify_result",
                                    reinterpret_cast<void *>(&ICReplacementSSLGetVerifyResult),
                                    reinterpret_cast<void **>(&ICOriginalSSLGetVerifyResult))) {
        count++;
    }

    if (ICInstallNativeFunctionHook("X509_verify_cert",
                                    reinterpret_cast<void *>(&ICReplacementX509VerifyCert),
                                    reinterpret_cast<void **>(&ICOriginalX509VerifyCert))) {
        count++;
    }

    if (ICInstallNativeFunctionHook("SSL_get_psk_identity",
                                    reinterpret_cast<void *>(&ICReplacementSSLGetPSKIdentity),
                                    reinterpret_cast<void **>(&ICOriginalSSLGetPSKIdentity))) {
        count++;
    }

    return count;
}

#pragma mark - HTTP/3 fallback

static int (*ICOriginalConnect)(int socket, const struct sockaddr *address, socklen_t length) = NULL;
static ssize_t (*ICOriginalSendTo)(int socket,
                                   const void *buffer,
                                   size_t length,
                                   int flags,
                                   const struct sockaddr *address,
                                   socklen_t addressLength) = NULL;
static ssize_t (*ICOriginalSendMessage)(int socket, const struct msghdr *message, int flags) = NULL;

static BOOL ICIsDatagramSocket(int socket) {
    int type = 0;
    socklen_t length = sizeof(type);
    return getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &length) == 0 && type == SOCK_DGRAM;
}

static BOOL ICIsHTTPSAddress(const struct sockaddr *address) {
    if (!address) {
        return NO;
    }
    if (address->sa_family == AF_INET) {
        return ntohs(reinterpret_cast<const struct sockaddr_in *>(address)->sin_port) == 443;
    }
    if (address->sa_family == AF_INET6) {
        return ntohs(reinterpret_cast<const struct sockaddr_in6 *>(address)->sin6_port) == 443;
    }
    return NO;
}

static int ICReplacementConnect(int socket, const struct sockaddr *address, socklen_t length) {
    if (ICIsHTTPSAddress(address) && ICIsDatagramSocket(socket)) {
        ICRecordHit(ICHookCategoryQUIC);
        errno = ENETUNREACH;
        return -1;
    }
    return ICOriginalConnect ? ICOriginalConnect(socket, address, length) : -1;
}

static ssize_t ICReplacementSendTo(int socket,
                                   const void *buffer,
                                   size_t length,
                                   int flags,
                                   const struct sockaddr *address,
                                   socklen_t addressLength) {
    if (ICIsHTTPSAddress(address) && ICIsDatagramSocket(socket)) {
        ICRecordHit(ICHookCategoryQUIC);
        errno = ENETUNREACH;
        return -1;
    }
    return ICOriginalSendTo
        ? ICOriginalSendTo(socket, buffer, length, flags, address, addressLength)
        : -1;
}

static ssize_t ICReplacementSendMessage(int socket, const struct msghdr *message, int flags) {
    const struct sockaddr *address = message
        ? reinterpret_cast<const struct sockaddr *>(message->msg_name)
        : NULL;
    if (ICIsHTTPSAddress(address) && ICIsDatagramSocket(socket)) {
        ICRecordHit(ICHookCategoryQUIC);
        errno = ENETUNREACH;
        return -1;
    }
    return ICOriginalSendMessage ? ICOriginalSendMessage(socket, message, flags) : -1;
}

static NSUInteger ICInstallHTTP3FallbackHooks(void) {
    NSUInteger count = ICInstallQuicConfigurationHooks();
    count += ICInstallFunctionHook("connect",
                                   reinterpret_cast<void *>(&ICReplacementConnect),
                                   reinterpret_cast<void **>(&ICOriginalConnect)) ? 1 : 0;
    count += ICInstallFunctionHook("sendto",
                                   reinterpret_cast<void *>(&ICReplacementSendTo),
                                   reinterpret_cast<void **>(&ICOriginalSendTo)) ? 1 : 0;
    count += ICInstallFunctionHook("sendmsg",
                                   reinterpret_cast<void *>(&ICReplacementSendMessage),
                                   reinterpret_cast<void **>(&ICOriginalSendMessage)) ? 1 : 0;
    return count;
}

static void ICRecordInstalledHooks(NSUInteger count) {
    if (count == 0) {
        return;
    }
    @synchronized (NSProcessInfo.processInfo) {
        ICInstalledHookTotal += count;
    }
}

static void ICInstallAvailableHooks(void) {
    NSUInteger installed = 0;
    if (ICTLSHooksEnabled) {
        NSUInteger systemHooks = ICInstallSecurityHooks() + ICInstallNetworkFrameworkHooks();
        NSUInteger urlHooks = ICInstallObjectiveCHooks();
        NSUInteger ttHooks = ICInstallTTNetHooks();
        ICRecordCategory(ICHookCategorySystem, systemHooks);
        ICRecordCategory(ICHookCategoryURLSession, urlHooks);
        ICRecordCategory(ICHookCategoryTTNet, ttHooks);
        installed += systemHooks + urlHooks + ttHooks;
    }
    if (ICNativeTLSHooksEnabled) {
        NSUInteger nativeHooks = ICInstallNativeTLSHooks();
        ICRecordCategory(ICHookCategoryNativeTLS, nativeHooks);
        installed += nativeHooks;
    }
    if (ICHTTP3FallbackEnabled) {
        NSUInteger quicHooks = ICInstallHTTP3FallbackHooks();
        ICRecordCategory(ICHookCategoryQUIC, quicHooks);
        installed += quicHooks;
    }
    ICRecordInstalledHooks(installed);
    if (installed > 0) {
        ICLog(@"installed %lu new hooks (%lu total)",
              (unsigned long)installed,
              (unsigned long)ICInstalledTLSHookCount());
    }
}

static void ICImageAdded(const struct mach_header *header, intptr_t slide) {
    bool expected = false;
    if (!ICHookQueue ||
        !atomic_compare_exchange_strong(&ICHookScanQueued, &expected, true)) {
        return;
    }
    dispatch_async(ICHookQueue, ^{
        ICInstallAvailableHooks();
        atomic_store(&ICHookScanQueued, false);
    });
}

void ICInstallTLSHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier ?: @"unknown";
#if defined(IOSCAPTURE_DIRECT_INJECTION)
        ICTLSHooksEnabled = YES;
        ICNativeTLSHooksEnabled = YES;
        ICHTTP3FallbackEnabled = YES;
#else
        ICTLSHooksEnabled = ICBoolPreference(ICTLSBypassEnabledKey, YES);
        ICNativeTLSHooksEnabled = ICBoolPreference(ICNativeTLSBypassEnabledKey, NO);
        ICHTTP3FallbackEnabled = ICBoolPreference(ICHTTP3FallbackEnabledKey, YES);
#endif

        ICHookQueue = dispatch_queue_create("com.ioscapture.runtime-hooks", DISPATCH_QUEUE_SERIAL);
        BOOL runtimeAvailable = ICHookRuntimeAvailable();
        ICInstallAvailableHooks();
        _dyld_register_func_for_add_image(&ICImageAdded);
        ICLog(@"active in %@, runtime=%@, hooks=%lu",
              bundleIdentifier,
              runtimeAvailable ? @"ready" : @"missing",
              (unsigned long)ICInstalledTLSHookCount());
    });
}
