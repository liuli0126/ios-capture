#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "ICTLSHooks.h"
#import "ICPreferences.h"

#if defined(IOSCAPTURE_DIRECT_INJECTION)
static UIWindow *ICActiveWindow(void) {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] ||
            scene.activationState != UISceneActivationStateForegroundActive) {
            continue;
        }
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window.isKeyWindow) {
                return window;
            }
        }
    }
    return UIApplication.sharedApplication.keyWindow;
}

static void ICShowHookStatus(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = ICActiveWindow();
        if (!window || [window viewWithTag:0x1C150001]) {
            return;
        }

        NSUInteger hookCount = ICInstalledTLSHookCount();
        BOOL runtimeReady = ICHookRuntimeAvailable();
        CGFloat width = MAX(220.0, CGRectGetWidth(window.bounds) - 32.0);
        CGFloat top = window.safeAreaInsets.top + 8.0;
        UILabel *banner = [[UILabel alloc] initWithFrame:CGRectMake(16.0, top, width, 44.0)];
        banner.tag = 0x1C150001;
        banner.autoresizingMask = UIViewAutoresizingFlexibleWidth;
        banner.backgroundColor = runtimeReady && hookCount > 0
            ? [UIColor colorWithRed:0.08 green:0.46 blue:0.27 alpha:0.96]
            : [UIColor colorWithRed:0.72 green:0.16 blue:0.14 alpha:0.96];
        banner.textColor = UIColor.whiteColor;
        banner.font = [UIFont systemFontOfSize:14.0 weight:UIFontWeightSemibold];
        banner.textAlignment = NSTextAlignmentCenter;
        banner.layer.cornerRadius = 7.0;
        banner.layer.masksToBounds = YES;
        banner.text = runtimeReady
            ? [NSString stringWithFormat:@"iOS Capture active - %lu hooks", (unsigned long)hookCount]
            : @"iOS Capture: ElleKit Hook API missing";
        banner.alpha = 0.0;
        [window addSubview:banner];

        [UIView animateWithDuration:0.2 animations:^{
            banner.alpha = 1.0;
        } completion:^(BOOL finished) {
            [UIView animateWithDuration:0.25
                                  delay:4.0
                                options:UIViewAnimationOptionCurveEaseInOut
                             animations:^{ banner.alpha = 0.0; }
                             completion:^(BOOL done) { [banner removeFromSuperview]; }];
        }];
    });
}
#endif

%ctor {
    @autoreleasepool {
#if defined(IOSCAPTURE_DIRECT_INJECTION)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            ICInstallTLSHooks();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                ICShowHookStatus();
            });
        });
#else
        ICMarkCurrentProcessLoaded();

        if (!ICIsCurrentProcessSelected()) {
            return;
        }

        ICInstallTLSHooks();
        ICMarkCurrentProcessInjected();
#endif
    }
}
