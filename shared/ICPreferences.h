#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

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

nullable id ICCopyPreference(NSString *key);
void ICSetPreference(NSString *key, nullable id value);

BOOL ICIsCurrentProcessSelected(void);
void ICMarkCurrentProcessInjected(void);
NSString *ICJailbreakEnvironmentDescription(void);

NS_ASSUME_NONNULL_END
