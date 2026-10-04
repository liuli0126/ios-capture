#import "ICPreferences.h"

#import <CoreFoundation/CoreFoundation.h>
#import <unistd.h>

NSString * const ICPreferencesDomain = @"com.ioscapture.settings";
NSString * const ICPreferencesChangedNotification = @"com.ioscapture.preferences.changed";

NSString * const ICEnabledKey = @"enabled";
NSString * const ICTLSBypassEnabledKey = @"tlsBypassEnabled";
NSString * const ICNativeTLSBypassEnabledKey = @"nativeTLSBypassEnabled";
NSString * const ICDiagnosticsEnabledKey = @"diagnosticsEnabled";
NSString * const ICSelectedBundlesKey = @"selectedBundleIdentifiers";
NSString * const ICLastInjectedBundleKey = @"lastInjectedBundleIdentifier";
NSString * const ICLastInjectedDateKey = @"lastInjectedDate";

id ICCopyPreference(NSString *key) {
    if (key.length == 0) {
        return nil;
    }
    CFPropertyListRef value = CFPreferencesCopyAppValue((__bridge CFStringRef)key,
                                                        (__bridge CFStringRef)ICPreferencesDomain);
    return CFBridgingRelease(value);
}

void ICSetPreference(NSString *key, id value) {
    if (key.length == 0) {
        return;
    }
    CFPreferencesSetAppValue((__bridge CFStringRef)key,
                             value ? (__bridge CFPropertyListRef)value : NULL,
                             (__bridge CFStringRef)ICPreferencesDomain);
    CFPreferencesAppSynchronize((__bridge CFStringRef)ICPreferencesDomain);
}

BOOL ICBoolPreference(NSString *key, BOOL fallback) {
    id value = ICCopyPreference(key);
    return [value respondsToSelector:@selector(boolValue)] ? [value boolValue] : fallback;
}

void ICSetBoolPreference(NSString *key, BOOL value) {
    ICSetPreference(key, @(value));
}

NSArray<NSString *> *ICSelectedBundleIdentifiers(void) {
    id value = ICCopyPreference(ICSelectedBundlesKey);
    if (![value isKindOfClass:[NSArray class]]) {
        return @[];
    }

    NSMutableOrderedSet<NSString *> *result = [NSMutableOrderedSet orderedSet];
    for (id candidate in (NSArray *)value) {
        if ([candidate isKindOfClass:[NSString class]] && [candidate length] > 0) {
            [result addObject:candidate];
        }
    }
    return result.array;
}

void ICSetSelectedBundleIdentifiers(NSArray<NSString *> *bundleIdentifiers) {
    NSMutableOrderedSet<NSString *> *clean = [NSMutableOrderedSet orderedSet];
    for (id candidate in bundleIdentifiers ?: @[]) {
        if ([candidate isKindOfClass:[NSString class]] && [candidate length] > 0) {
            [clean addObject:candidate];
        }
    }
    ICSetPreference(ICSelectedBundlesKey, clean.array);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         (__bridge CFStringRef)ICPreferencesChangedNotification,
                                         NULL,
                                         NULL,
                                         true);
}

BOOL ICIsCurrentProcessSelected(void) {
    if (!ICBoolPreference(ICEnabledKey, YES)) {
        return NO;
    }

    NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
    if (bundleIdentifier.length == 0 ||
        [bundleIdentifier isEqualToString:@"com.ioscapture.manager"] ||
        [bundleIdentifier isEqualToString:@"com.proxy.pin"]) {
        return NO;
    }
    return [ICSelectedBundleIdentifiers() containsObject:bundleIdentifier];
}

void ICMarkCurrentProcessInjected(void) {
    NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
    if (bundleIdentifier.length == 0) {
        return;
    }
    ICSetPreference(ICLastInjectedBundleKey, bundleIdentifier);
    ICSetPreference(ICLastInjectedDateKey, NSDate.date);
}

NSString *ICJailbreakEnvironmentDescription(void) {
    if (access("/var/jb", F_OK) == 0) {
        return @"Rootless (/var/jb)";
    }
    return @"Rootful";
}
