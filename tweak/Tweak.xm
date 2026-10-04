#import <Foundation/Foundation.h>

#import "ICTLSHooks.h"
#import "ICPreferences.h"

%ctor {
    @autoreleasepool {
        if (!ICIsCurrentProcessSelected()) {
            return;
        }

        ICInstallTLSHooks();
        ICMarkCurrentProcessInjected();
    }
}
