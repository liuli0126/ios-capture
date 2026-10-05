#import <Foundation/Foundation.h>

#import "ICTLSHooks.h"
#import "ICPreferences.h"

%ctor {
    @autoreleasepool {
#if defined(IOSCAPTURE_DIRECT_INJECTION)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            ICInstallTLSHooks();
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
