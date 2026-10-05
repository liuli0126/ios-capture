#import <Foundation/Foundation.h>

#import "ICTLSHooks.h"
#import "ICPreferences.h"

%ctor {
    @autoreleasepool {
        ICMarkCurrentProcessLoaded();

#if defined(IOSCAPTURE_DIRECT_INJECTION)
        ICInstallTLSHooks();
        ICMarkCurrentProcessInjected();
#else
        if (!ICIsCurrentProcessSelected()) {
            return;
        }

        ICInstallTLSHooks();
        ICMarkCurrentProcessInjected();
#endif
    }
}
