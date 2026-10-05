#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

void ICInstallTLSHooks(void);
NSUInteger ICInstalledTLSHookCount(void);
BOOL ICHookRuntimeAvailable(void);
NSString *ICCopyTLSHookStatusSummary(void);

NS_ASSUME_NONNULL_END
