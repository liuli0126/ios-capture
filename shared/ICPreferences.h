#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

FOUNDATION_EXPORT NSString * const ICPreferencesDomain;
FOUNDATION_EXPORT NSString * const ICPreferencesChangedNotification;

FOUNDATION_EXPORT NSString * const ICEnabledKey;
FOUNDATION_EXPORT NSString * const ICTLSBypassEnabledKey;
FOUNDATION_EXPORT NSString * const ICNativeTLSBypassEnabledKey;
FOUNDATION_EXPORT NSString * const ICDiagnosticsEnabledKey;
FOUNDATION_EXPORT NSString * const ICSelectedBundlesKey;
FOUNDATION_EXPORT NSString * const ICLastInjectedBundleKey;
FOUNDATION_EXPORT NSString * const ICLastInjectedDateKey;

NSArray<NSString *> *ICSelectedBundleIdentifiers(void);
void ICSetSelectedBundleIdentifiers(NSArray<NSString *> *bundleIdentifiers);

BOOL ICBoolPreference(NSString *key, BOOL fallback);
void ICSetBoolPreference(NSString *key, BOOL value);

id _Nullable ICCopyPreference(NSString *key);
void ICSetPreference(NSString *key, id _Nullable value);

BOOL ICIsCurrentProcessSelected(void);
void ICMarkCurrentProcessInjected(void);
NSString *ICJailbreakEnvironmentDescription(void);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
