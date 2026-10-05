#import <Foundation/Foundation.h>

#import "ICTLSHooks.h"
#import "ICPreferences.h"

%ctor {
    @autoreleasepool {
#if defined(IOSCAPTURE_DIRECT_INJECTION)
        ICInstallTLSHooks();
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
