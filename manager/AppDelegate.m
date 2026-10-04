#import "AppDelegate.h"

#import "RootViewController.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];

    RootViewController *root = [[RootViewController alloc] init];
    UINavigationController *navigation = [[UINavigationController alloc] initWithRootViewController:root];
    navigation.navigationBar.prefersLargeTitles = NO;
    navigation.toolbar.translucent = YES;

    self.window.rootViewController = navigation;
    [self.window makeKeyAndVisible];
    return YES;
}

@end
