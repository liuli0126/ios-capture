#import "RootViewController.h"

#import "ICPreferences.h"

#import <objc/runtime.h>
#import <spawn.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

@interface LSApplicationProxy : NSObject
@property (nonatomic, readonly) NSString *applicationIdentifier;
@property (nonatomic, readonly) NSString *localizedName;
@property (nonatomic, readonly) NSString *applicationType;
@property (nonatomic, readonly) NSString *bundleExecutable;
@end

@interface LSApplicationWorkspace : NSObject
+ (instancetype)defaultWorkspace;
- (NSArray<LSApplicationProxy *> *)allInstalledApplications;
- (BOOL)openApplicationWithBundleID:(NSString *)bundleIdentifier;
@end

@interface ICBundleSwitch : UISwitch
@property (nonatomic, copy) NSString *bundleIdentifier;
@end

@implementation ICBundleSwitch
@end

@interface ICOptionSwitch : UISwitch
@property (nonatomic, copy) NSString *preferenceKey;
@end

@implementation ICOptionSwitch
@end

@interface RootViewController ()
@property (nonatomic, strong) NSArray<LSApplicationProxy *> *applications;
@property (nonatomic, strong) NSArray<LSApplicationProxy *> *filteredApplications;
@property (nonatomic, strong) NSMutableSet<NSString *> *selectedBundles;
@property (nonatomic, strong) UISearchController *searchController;
@property (nonatomic, assign) BOOL proxyPinInstalled;
@end

@implementation RootViewController

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _selectedBundles = [NSMutableSet setWithArray:ICSelectedBundleIdentifiers()];
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.title = @"iOS Capture";
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemSave
        target:self
        action:@selector(savePreferences)];

    self.searchController = [[UISearchController alloc] initWithSearchResultsController:nil];
    self.searchController.obscuresBackgroundDuringPresentation = NO;
    self.searchController.searchResultsUpdater = self;
    self.searchController.searchBar.placeholder = @"搜索 App";
    self.navigationItem.searchController = self.searchController;
    self.definesPresentationContext = YES;

    UIBarButtonItem *openProxy = [[UIBarButtonItem alloc] initWithTitle:@"打开 ProxyPin"
                                                                  style:UIBarButtonItemStylePlain
                                                                 target:self
                                                                 action:@selector(openProxyPin)];
    UIBarButtonItem *flex = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil];
    UIBarButtonItem *apply = [[UIBarButtonItem alloc] initWithTitle:@"应用并重启"
                                                              style:UIBarButtonItemStyleDone
                                                             target:self
                                                             action:@selector(applyAndRestart)];
    self.toolbarItems = @[openProxy, flex, apply];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(reloadStatus)
                                                 name:UIApplicationDidBecomeActiveNotification
                                               object:nil];
    [self loadApplications];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.navigationController setToolbarHidden:NO animated:animated];
    [self reloadStatus];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)loadApplications {
    Class workspaceClass = objc_getClass("LSApplicationWorkspace");
    LSApplicationWorkspace *workspace = [workspaceClass respondsToSelector:@selector(defaultWorkspace)]
        ? [workspaceClass defaultWorkspace]
        : nil;
    NSArray *installed = [workspace respondsToSelector:@selector(allInstalledApplications)]
        ? [workspace allInstalledApplications]
        : @[];

    NSMutableArray<LSApplicationProxy *> *userApplications = [NSMutableArray array];
    BOOL foundProxyPin = NO;
    for (LSApplicationProxy *proxy in installed) {
        NSString *bundleIdentifier = proxy.applicationIdentifier;
        if (bundleIdentifier.length == 0) {
            continue;
        }
        if ([bundleIdentifier isEqualToString:@"com.proxy.pin"]) {
            foundProxyPin = YES;
            continue;
        }
        if ([bundleIdentifier isEqualToString:@"com.ioscapture.manager"] ||
            [bundleIdentifier hasPrefix:@"com.apple."]) {
            continue;
        }
        NSString *applicationType = proxy.applicationType;
        if (applicationType.length > 0 && ![applicationType isEqualToString:@"User"]) {
            continue;
        }
        [userApplications addObject:proxy];
    }

    [userApplications sortUsingComparator:^NSComparisonResult(LSApplicationProxy *left,
                                                               LSApplicationProxy *right) {
        NSString *leftName = left.localizedName ?: left.applicationIdentifier;
        NSString *rightName = right.localizedName ?: right.applicationIdentifier;
        return [leftName localizedCaseInsensitiveCompare:rightName];
    }];

    self.proxyPinInstalled = foundProxyPin;
    self.applications = userApplications;
    [self updateSearchResultsForSearchController:self.searchController];
}

- (void)reloadStatus {
    self.selectedBundles = [NSMutableSet setWithArray:ICSelectedBundleIdentifiers()];
    [self loadApplications];
    [self.tableView reloadData];
}

#pragma mark - Search

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController {
    NSString *query = [searchController.searchBar.text stringByTrimmingCharactersInSet:
                       NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (query.length == 0) {
        self.filteredApplications = self.applications;
    } else {
        NSPredicate *predicate = [NSPredicate predicateWithBlock:^BOOL(LSApplicationProxy *proxy,
                                                                      NSDictionary *bindings) {
            NSString *name = proxy.localizedName ?: @"";
            NSString *bundleIdentifier = proxy.applicationIdentifier ?: @"";
            return [name localizedCaseInsensitiveContainsString:query] ||
                   [bundleIdentifier localizedCaseInsensitiveContainsString:query];
        }];
        self.filteredApplications = [self.applications filteredArrayUsingPredicate:predicate];
    }
    [self.tableView reloadData];
}

#pragma mark - Table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 3;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0) {
        return 4;
    }
    if (section == 1) {
        return 4;
    }
    return self.filteredApplications.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) {
        return @"状态";
    }
    if (section == 1) {
        return @"抓包兼容";
    }
    return [NSString stringWithFormat:@"目标 App · %lu", (unsigned long)self.selectedBundles.count];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    NSString *reuseIdentifier = indexPath.section == 2 ? @"Application" : @"Setting";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:reuseIdentifier];
    if (!cell) {
        UITableViewCellStyle style = indexPath.section == 2
            ? UITableViewCellStyleSubtitle
            : UITableViewCellStyleValue1;
        cell = [[UITableViewCell alloc] initWithStyle:style reuseIdentifier:reuseIdentifier];
    }

    cell.accessoryView = nil;
    cell.accessoryType = UITableViewCellAccessoryNone;
    cell.imageView.image = nil;
    cell.detailTextLabel.text = nil;

    if (indexPath.section == 0) {
        [self configureStatusCell:cell row:indexPath.row];
    } else if (indexPath.section == 1) {
        [self configureOptionCell:cell row:indexPath.row];
    } else {
        [self configureApplicationCell:cell row:indexPath.row];
    }
    return cell;
}

- (void)configureStatusCell:(UITableViewCell *)cell row:(NSInteger)row {
    if (row == 0) {
        cell.textLabel.text = @"越狱环境";
        cell.detailTextLabel.text = ICJailbreakEnvironmentDescription();
        return;
    }
    if (row == 1) {
        cell.textLabel.text = @"ProxyPin";
        cell.detailTextLabel.text = self.proxyPinInstalled ? @"已安装" : @"未安装";
        cell.detailTextLabel.textColor = self.proxyPinInstalled ? UIColor.systemGreenColor : UIColor.systemRedColor;
        return;
    }

    NSString *bundleKey = row == 2 ? ICLastLoadedBundleKey : ICLastInjectedBundleKey;
    NSString *dateKey = row == 2 ? ICLastLoadedDateKey : ICLastInjectedDateKey;
    cell.textLabel.text = row == 2 ? @"dylib 加载" : @"Hook 启用";
    NSString *bundleIdentifier = ICCopyPreference(bundleKey);
    NSDate *date = ICCopyPreference(dateKey);
    if ([bundleIdentifier isKindOfClass:NSString.class] && bundleIdentifier.length > 0) {
        if ([date isKindOfClass:NSDate.class]) {
            NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
            formatter.dateFormat = @"HH:mm";
            cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ · %@",
                                         bundleIdentifier,
                                         [formatter stringFromDate:date]];
        } else {
            cell.detailTextLabel.text = bundleIdentifier;
        }
    } else {
        cell.detailTextLabel.text = @"等待目标 App";
    }
}

- (void)configureOptionCell:(UITableViewCell *)cell row:(NSInteger)row {
    NSArray<NSDictionary *> *options = @[
        @{@"title": @"插件启用", @"key": ICEnabledKey, @"default": @YES},
        @{@"title": @"TLS 兼容", @"key": ICTLSBypassEnabledKey, @"default": @YES},
        @{@"title": @"Native TLS", @"key": ICNativeTLSBypassEnabledKey, @"default": @NO},
        @{@"title": @"诊断日志", @"key": ICDiagnosticsEnabledKey, @"default": @YES},
    ];
    NSDictionary *option = options[(NSUInteger)row];
    NSString *key = option[@"key"];
    BOOL fallback = [option[@"default"] boolValue];

    cell.textLabel.text = option[@"title"];
    ICOptionSwitch *toggle = [[ICOptionSwitch alloc] init];
    toggle.preferenceKey = key;
    toggle.on = ICBoolPreference(key, fallback);
    [toggle addTarget:self action:@selector(optionChanged:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = toggle;
}

- (void)configureApplicationCell:(UITableViewCell *)cell row:(NSInteger)row {
    LSApplicationProxy *proxy = self.filteredApplications[(NSUInteger)row];
    NSString *bundleIdentifier = proxy.applicationIdentifier;
    cell.textLabel.text = proxy.localizedName ?: bundleIdentifier;
    cell.detailTextLabel.text = bundleIdentifier;
    cell.imageView.image = [UIImage systemImageNamed:@"app"];

    ICBundleSwitch *toggle = [[ICBundleSwitch alloc] init];
    toggle.bundleIdentifier = bundleIdentifier;
    toggle.on = [self.selectedBundles containsObject:bundleIdentifier];
    [toggle addTarget:self action:@selector(applicationSelectionChanged:)
     forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = toggle;
}

#pragma mark - Actions

- (void)optionChanged:(ICOptionSwitch *)sender {
    ICSetBoolPreference(sender.preferenceKey, sender.isOn);
}

- (void)applicationSelectionChanged:(ICBundleSwitch *)sender {
    if (sender.isOn) {
        [self.selectedBundles addObject:sender.bundleIdentifier];
    } else {
        [self.selectedBundles removeObject:sender.bundleIdentifier];
    }
    [self.tableView reloadSections:[NSIndexSet indexSetWithIndex:2]
                  withRowAnimation:UITableViewRowAnimationNone];
}

- (void)savePreferences {
    NSArray *sorted = [self.selectedBundles.allObjects sortedArrayUsingSelector:@selector(compare:)];
    ICSetSelectedBundleIdentifiers(sorted);
    [self showMessage:@"已保存" detail:[NSString stringWithFormat:@"已选择 %lu 个 App",
                                       (unsigned long)sorted.count]];
}

- (void)openProxyPin {
    Class workspaceClass = objc_getClass("LSApplicationWorkspace");
    LSApplicationWorkspace *workspace = [workspaceClass respondsToSelector:@selector(defaultWorkspace)]
        ? [workspaceClass defaultWorkspace]
        : nil;
    BOOL opened = [workspace respondsToSelector:@selector(openApplicationWithBundleID:)] &&
                  [workspace openApplicationWithBundleID:@"com.proxy.pin"];
    if (!opened) {
        [self showMessage:@"ProxyPin 未打开" detail:@"请先安装 ProxyPin iOS 版"];
    }
}

- (void)applyAndRestart {
    NSArray *sorted = [self.selectedBundles.allObjects sortedArrayUsingSelector:@selector(compare:)];
    ICSetSelectedBundleIdentifiers(sorted);
    ICSetPreference(ICLastLoadedBundleKey, nil);
    ICSetPreference(ICLastLoadedDateKey, nil);
    ICSetPreference(ICLastInjectedBundleKey, nil);
    ICSetPreference(ICLastInjectedDateKey, nil);

    NSMutableSet<NSString *> *executables = [NSMutableSet set];
    for (LSApplicationProxy *proxy in self.applications) {
        if ([self.selectedBundles containsObject:proxy.applicationIdentifier] &&
            proxy.bundleExecutable.length > 0) {
            [executables addObject:proxy.bundleExecutable];
        }
    }

    NSUInteger restarted = 0;
    for (NSString *executable in executables) {
        if ([self terminateExecutable:executable]) {
            restarted++;
        }
    }

    [self showMessage:@"配置已应用"
                detail:[NSString stringWithFormat:@"已结束 %lu 个目标进程",
                        (unsigned long)restarted]];
}

- (BOOL)terminateExecutable:(NSString *)executable {
    if (executable.length == 0) {
        return NO;
    }

    const char *candidatePaths[] = {"/var/jb/usr/bin/killall", "/usr/bin/killall", NULL};
    const char *killallPath = NULL;
    for (NSUInteger index = 0; candidatePaths[index] != NULL; index++) {
        if (access(candidatePaths[index], X_OK) == 0) {
            killallPath = candidatePaths[index];
            break;
        }
    }
    if (!killallPath) {
        return NO;
    }

    pid_t process = 0;
    const char *name = executable.UTF8String;
    char *const arguments[] = {
        (char *)killallPath,
        (char *)"-9",
        (char *)name,
        NULL,
    };
    int result = posix_spawn(&process, killallPath, NULL, NULL, arguments, environ);
    if (result != 0) {
        return NO;
    }
    int status = 0;
    waitpid(process, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

- (void)showMessage:(NSString *)title detail:(NSString *)detail {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:detail
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
