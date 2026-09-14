#import <AppKit/AppKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <WebKit/WebKit.h>
#import <sys/stat.h>
#import <unistd.h>

@interface RATAppDelegate : NSObject <NSApplicationDelegate, WKScriptMessageHandler, WKNavigationDelegate>
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) WKWebView *webView;
@property(nonatomic, strong) NSData *lastReport;
@property(nonatomic, copy) NSString *lastFileScanPath;
@property(nonatomic, assign) BOOL scanning;
- (NSString *)responseErrorFromResult:(NSDictionary *)result fallback:(NSString *)fallback;
- (BOOL)isValidSHA256:(NSString *)digest;
- (BOOL)isValidCDHash:(NSString *)digest;
- (void)enableRecovery;
- (void)recoverFiles;
- (void)resumeRecovery;
- (void)planFindingException:(NSDictionary *)exception fileScan:(BOOL)fileScan;
- (NSArray<NSString *> *)exceptionArgumentsForFinding:(NSDictionary *)exception apply:(BOOL)apply;
- (void)listExceptions;
- (void)planRemoveException:(NSString *)identifier;
- (void)selectFileScan;
- (void)startFileScanPath:(NSString *)path;
@end

@implementation RATAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    WKUserContentController *messages = [[WKUserContentController alloc] init];
    [messages addScriptMessageHandler:self name:@"rattler"];

    WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];
    configuration.userContentController = messages;
    configuration.preferences.javaScriptCanOpenWindowsAutomatically = NO;

    self.webView = [[WKWebView alloc] initWithFrame:NSZeroRect configuration:configuration];
    self.webView.navigationDelegate = self;
    self.webView.allowsMagnification = NO;
    self.webView.wantsLayer = YES;
    self.webView.layer.backgroundColor = [NSColor colorWithRed:0.035 green:0.047 blue:0.065 alpha:1].CGColor;

    NSWindowStyleMask style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
        NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable | NSWindowStyleMaskFullSizeContentView;
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 1180, 760)
                                               styleMask:style
                                                 backing:NSBackingStoreBuffered
                                                   defer:NO];
    self.window.title = @"RATtler";
    self.window.titleVisibility = NSWindowTitleHidden;
    self.window.titlebarAppearsTransparent = YES;
    self.window.backgroundColor = [NSColor colorWithRed:0.035 green:0.047 blue:0.065 alpha:1];
    self.window.minSize = NSMakeSize(980, 650);
    self.window.contentView = self.webView;
    self.window.collectionBehavior = NSWindowCollectionBehaviorFullScreenPrimary;
    [self.window setFrameAutosaveName:@"RATtlerMainWindow"];
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];

    NSURL *page = [[NSBundle mainBundle] URLForResource:@"index" withExtension:@"html" subdirectory:@"Web"];
    NSURL *directory = [page URLByDeletingLastPathComponent];
    if (page != nil) {
        [self.webView loadFileURL:page allowingReadAccessToURL:directory];
    } else {
        [self showNativeError:@"The RATtler interface is missing from this app build."];
    }
    [NSApp activateIgnoringOtherApps:YES];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    (void)sender;
    return YES;
}

- (BOOL)applicationSupportsSecureRestorableState:(NSApplication *)application {
    (void)application;
    return YES;
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    (void)webView;
    (void)navigation;
    [self sendCapabilities];
    [self startScan];
}

- (void)webView:(WKWebView *)webView
    decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction
                   decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    (void)webView;
    NSURL *url = navigationAction.request.URL;
    if (navigationAction.navigationType == WKNavigationTypeLinkActivated && !url.isFileURL) {
        if (url != nil && [@[@"https", @"http"] containsObject:url.scheme.lowercaseString]) {
            [[NSWorkspace sharedWorkspace] openURL:url];
        }
        decisionHandler(WKNavigationActionPolicyCancel);
        return;
    }
    decisionHandler(WKNavigationActionPolicyAllow);
}

- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    (void)userContentController;
    if (![message.body isKindOfClass:[NSDictionary class]]) return;
    NSString *action = ((NSDictionary *)message.body)[@"action"];
    if ([action isEqualToString:@"scan"]) {
        [self startScan];
    } else if ([action isEqualToString:@"baseline"]) {
        [self createBaseline];
    } else if ([action isEqualToString:@"export"]) {
        [self exportReport];
    } else if ([action isEqualToString:@"reveal"]) {
        NSURL *directory = [self applicationDataDirectory];
        [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[directory]];
    } else if ([action isEqualToString:@"revealApp"]) {
        [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[[NSBundle mainBundle].bundleURL]];
    } else if ([action isEqualToString:@"revealQuarantine"]) {
        NSURL *directory = [[self applicationDataDirectory] URLByAppendingPathComponent:@"quarantine"
                                                                              isDirectory:YES];
        [[NSFileManager defaultManager] createDirectoryAtURL:directory
                                 withIntermediateDirectories:YES
                                                  attributes:@{NSFilePosixPermissions: @0700}
                                                       error:nil];
        chmod(directory.fileSystemRepresentation, 0700);
        [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[directory]];
    } else if ([action isEqualToString:@"quarantine"]) {
        NSString *path = ((NSDictionary *)message.body)[@"path"];
        NSString *ruleID = ((NSDictionary *)message.body)[@"ruleId"];
        BOOL fileScan = [((NSDictionary *)message.body)[@"fileScan"] boolValue];
        [self planQuarantinePath:path ruleID:ruleID fileScan:fileScan];
    } else if ([action isEqualToString:@"listQuarantine"]) {
        [self listQuarantine];
    } else if ([action isEqualToString:@"restore"]) {
        NSString *identifier = ((NSDictionary *)message.body)[@"id"];
        [self planRestoreIdentifier:identifier];
    } else if ([action isEqualToString:@"addException"]) {
        NSDictionary *exception = [((NSDictionary *)message.body)[@"exception"] isKindOfClass:[NSDictionary class]]
            ? ((NSDictionary *)message.body)[@"exception"] : nil;
        BOOL fileScan = [((NSDictionary *)message.body)[@"fileScan"] boolValue];
        [self planFindingException:exception fileScan:fileScan];
    } else if ([action isEqualToString:@"listExceptions"]) {
        [self listExceptions];
    } else if ([action isEqualToString:@"removeException"]) {
        NSString *identifier = ((NSDictionary *)message.body)[@"id"];
        [self planRemoveException:identifier];
    } else if ([action isEqualToString:@"selectFileScan"]) {
        [self selectFileScan];
    } else if ([action isEqualToString:@"enableRecovery"]) {
        [self enableRecovery];
    } else if ([action isEqualToString:@"recoverFiles"]) {
        [self recoverFiles];
    } else if ([action isEqualToString:@"resumeRecovery"]) {
        [self resumeRecovery];
    } else if ([action isEqualToString:@"revealRecovery"]) {
        NSURL *directory = [[self applicationDataDirectory] URLByAppendingPathComponent:@"recovery"
                                                                              isDirectory:YES];
        [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[directory]];
    } else if ([action isEqualToString:@"capabilities"]) {
        [self sendCapabilities];
    }
}

- (NSURL *)applicationDataDirectory {
    NSURL *base = [[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory
                                                          inDomains:NSUserDomainMask] firstObject];
    NSURL *directory = [base URLByAppendingPathComponent:@"RATtler" isDirectory:YES];
    [[NSFileManager defaultManager] createDirectoryAtURL:directory
                             withIntermediateDirectories:YES
                                              attributes:@{NSFilePosixPermissions: @0700}
                                                   error:nil];
    chmod(directory.fileSystemRepresentation, 0700);
    return directory;
}

- (NSArray<NSString *> *)scanArguments {
    NSURL *directory = [self applicationDataDirectory];
    NSURL *state = [directory URLByAppendingPathComponent:@"state.json"];
    NSURL *journal = [directory URLByAppendingPathComponent:@"events.jsonl"];
    NSURL *baseline = [directory URLByAppendingPathComponent:@"baseline.json"];
    NSURL *nativeEvents = [directory URLByAppendingPathComponent:@"native-events.jsonl"];
    NSURL *ransomwareState = [directory URLByAppendingPathComponent:@"ransomware-state.json"];
    NSURL *exceptions = [directory URLByAppendingPathComponent:@"exceptions.json"];
    NSString *home = NSHomeDirectory();
    NSMutableArray<NSString *> *arguments = [NSMutableArray arrayWithArray:@[
        @"--state", state.path, @"--journal", journal.path,
        @"--ransomware-state", ransomwareState.path,
        @"--exceptions", exceptions.path,
        @"--ransomware-root", [home stringByAppendingPathComponent:@"Desktop"],
        @"--ransomware-root", [home stringByAppendingPathComponent:@"Documents"],
        @"--ransomware-root", [home stringByAppendingPathComponent:@"Pictures"],
        @"--exclude-pid", [NSString stringWithFormat:@"%d", getpid()], @"--pretty"
    ]];
    if ([[NSFileManager defaultManager] fileExistsAtPath:baseline.path]) {
        [arguments addObjectsFromArray:@[@"--baseline", baseline.path]];
    }
    if ([[NSFileManager defaultManager] fileExistsAtPath:nativeEvents.path]) {
        [arguments addObjectsFromArray:@[@"--native-events", nativeEvents.path]];
    }
    NSURL *recovery = [directory URLByAppendingPathComponent:@"recovery" isDirectory:YES];
    if ([[NSFileManager defaultManager] fileExistsAtPath:[[recovery URLByAppendingPathComponent:@"manifest.json"] path]]) {
        [arguments addObjectsFromArray:@[@"--recovery-store", recovery.path]];
    }
    return arguments;
}

- (NSArray<NSString *> *)recoveryBackupArguments {
    NSURL *store = [[self applicationDataDirectory] URLByAppendingPathComponent:@"recovery" isDirectory:YES];
    NSString *home = NSHomeDirectory();
    return @[
        @"recovery", @"backup", @"--store", store.path,
        @"--root", [home stringByAppendingPathComponent:@"Desktop"],
        @"--root", [home stringByAppendingPathComponent:@"Documents"],
        @"--root", [home stringByAppendingPathComponent:@"Pictures"],
        @"--apply", @"--pretty",
    ];
}

- (BOOL)recoveryEnabled {
    NSURL *manifest = [[[self applicationDataDirectory] URLByAppendingPathComponent:@"recovery"
                                                                        isDirectory:YES]
                       URLByAppendingPathComponent:@"manifest.json"];
    return [[NSFileManager defaultManager] fileExistsAtPath:manifest.path];
}

- (NSURL *)recoveryFreezeURL {
    return [[[self applicationDataDirectory] URLByAppendingPathComponent:@"recovery" isDirectory:YES]
            URLByAppendingPathComponent:@"frozen"];
}

- (NSURL *)recoveryErrorURL {
    return [[[self applicationDataDirectory] URLByAppendingPathComponent:@"recovery" isDirectory:YES]
            URLByAppendingPathComponent:@"backup-error"];
}

- (BOOL)recoveryFrozen {
    return [[NSFileManager defaultManager] fileExistsAtPath:[self recoveryFreezeURL].path];
}

- (BOOL)reportContainsRansomwareFinding:(NSDictionary *)report {
    NSDictionary *behavior = [report[@"behavior"] isKindOfClass:[NSDictionary class]] ? report[@"behavior"] : nil;
    NSArray *findings = [behavior[@"findings"] isKindOfClass:[NSArray class]] ? behavior[@"findings"] : @[];
    for (id item in findings) {
        if ([item isKindOfClass:[NSDictionary class]] && [item[@"category"] isEqualToString:@"ransomware"]) {
            return YES;
        }
    }
    return NO;
}

- (void)freezeRecoveryForReport:(NSDictionary *)report {
    if (![self recoveryEnabled] || ![self reportContainsRansomwareFinding:report]) return;
    NSData *marker = [@"Frozen after ransomware evidence.\n" dataUsingEncoding:NSUTF8StringEncoding];
    [marker writeToURL:[self recoveryFreezeURL] options:NSDataWritingAtomic error:nil];
    chmod([self recoveryFreezeURL].fileSystemRepresentation, 0600);
}

- (void)startScan {
    if (self.scanning) return;
    self.scanning = YES;
    [self sendObject:@{@"phase": @"scanning", @"message": @"Inspecting this Mac…"}
            function:@"receiveState"];
    NSArray<NSString *> *arguments = [self scanArguments];
    BOOL updateRecovery = [self recoveryEnabled] && ![self recoveryFrozen];
    NSArray<NSString *> *recoveryArguments = updateRecovery ? [self recoveryBackupArguments] : nil;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        if (recoveryArguments != nil) {
            NSDictionary *recoveryResult = [self runEngineArguments:recoveryArguments];
            NSURL *errorMarker = [self recoveryErrorURL];
            if ([recoveryResult[@"status"] intValue] == 0) {
                [[NSFileManager defaultManager] removeItemAtURL:errorMarker error:nil];
            } else {
                NSData *marker = [@"The latest automatic recovery backup failed.\n" dataUsingEncoding:NSUTF8StringEncoding];
                [marker writeToURL:errorMarker options:NSDataWritingAtomic error:nil];
                chmod(errorMarker.fileSystemRepresentation, 0600);
            }
        }
        NSDictionary *result = [self runEngineArguments:arguments];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.scanning = NO;
            NSData *output = result[@"output"];
            NSError *jsonError = nil;
            id report = output.length ? [NSJSONSerialization JSONObjectWithData:output options:0 error:&jsonError] : nil;
            if ([report isKindOfClass:[NSDictionary class]]) {
                self.lastReport = output;
                [self freezeRecoveryForReport:(NSDictionary *)report];
                [self sendData:output function:@"receiveReport"];
                [self sendObject:@{@"phase": @"ready", @"message": @"Scan completed"}
                        function:@"receiveState"];
            } else {
                NSString *detail = result[@"error"];
                if (detail.length == 0) detail = jsonError.localizedDescription ?: @"The detection engine returned no report.";
                [self sendObject:@{@"phase": @"error", @"message": detail}
                        function:@"receiveState"];
            }
            [self sendCapabilities];
        });
    });
}

- (void)createBaseline {
    if (self.scanning) return;
    self.scanning = YES;
    NSURL *baseline = [[self applicationDataDirectory] URLByAppendingPathComponent:@"baseline.json"];
    [self sendObject:@{@"phase": @"scanning", @"message": @"Creating integrity baseline…"}
            function:@"receiveState"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = [self runEngineArguments:@[@"--create-baseline", baseline.path, @"--pretty"]];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.scanning = NO;
            if ([result[@"status"] intValue] == 0) {
                [self sendObject:@{@"phase": @"ready", @"message": @"Integrity baseline created"}
                        function:@"receiveState"];
                [self sendCapabilities];
                [self startScan];
            } else {
                NSString *detail = result[@"error"];
                if (detail.length == 0) detail = @"The integrity baseline could not be created.";
                [self sendObject:@{@"phase": @"error", @"message": detail}
                        function:@"receiveState"];
            }
        });
    });
}

- (void)planQuarantinePath:(NSString *)path ruleID:(NSString *)ruleID fileScan:(BOOL)fileScan {
    if (self.scanning) return;
    if (![path isKindOfClass:[NSString class]] || !path.isAbsolutePath || path.length > 4096) {
        [self sendObject:@{@"phase": @"error", @"message": @"The finding does not contain a safe absolute file path."}
                function:@"receiveState"];
        return;
    }
    NSString *reason = [ruleID isKindOfClass:[NSString class]] && ruleID.length > 0 && ruleID.length < 128
        ? [NSString stringWithFormat:@"RATtler finding %@", ruleID]
        : @"RATtler operator review";
    NSString *store = [[[self applicationDataDirectory] URLByAppendingPathComponent:@"quarantine"
                                                                          isDirectory:YES] path];
    NSArray<NSString *> *planArguments = @[
        @"response", @"quarantine", path,
        @"--reason", reason, @"--store", store, @"--pretty",
    ];
    self.scanning = YES;
    [self sendObject:@{@"phase": @"scanning", @"message": @"Verifying the exact file before response…"}
            function:@"receiveState"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = [self runEngineArguments:planArguments];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSError *jsonError = nil;
            NSData *output = result[@"output"];
            NSDictionary *plan = output.length
                ? [NSJSONSerialization JSONObjectWithData:output options:0 error:&jsonError]
                : nil;
            NSString *digest = [plan isKindOfClass:[NSDictionary class]] ? plan[@"sha256"] : nil;
            NSString *plannedTarget = [plan[@"target"] isKindOfClass:[NSString class]] ? plan[@"target"] : nil;
            if ([result[@"status"] intValue] != 0 || ![self isValidSHA256:digest] ||
                !plannedTarget.isAbsolutePath) {
                self.scanning = NO;
                NSString *detail = [self responseErrorFromResult:result
                                                        fallback:jsonError.localizedDescription ?: @"The response plan could not be verified."];
                [self sendObject:@{@"phase": @"error", @"message": detail}
                        function:@"receiveState"];
                return;
            }

            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"Quarantine this exact file?";
            alert.informativeText = [NSString stringWithFormat:
                @"RATtler will move this file into protected local storage and remove its execute permission. "
                 "This does not stop an already-running process.\n\nPath: %@\nSHA-256: %@",
                plannedTarget, digest];
            alert.alertStyle = NSAlertStyleWarning;
            [alert addButtonWithTitle:@"Quarantine File"];
            [alert addButtonWithTitle:@"Cancel"];
            if ([alert runModal] != NSAlertFirstButtonReturn) {
                self.scanning = NO;
                [self sendObject:@{@"phase": @"ready", @"message": @"Quarantine cancelled"}
                        function:@"receiveState"];
                return;
            }

            NSArray<NSString *> *applyArguments = @[
                @"response", @"quarantine", path,
                @"--reason", reason, @"--store", store,
                @"--expected-sha256", digest, @"--apply", @"--pretty",
            ];
            [self sendObject:@{@"phase": @"scanning", @"message": @"Applying reviewed quarantine…"}
                    function:@"receiveState"];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                NSDictionary *appliedResult = [self runEngineArguments:applyArguments];
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.scanning = NO;
                    NSError *applyJSONError = nil;
                    NSData *appliedOutput = appliedResult[@"output"];
                    NSDictionary *applied = appliedOutput.length
                        ? [NSJSONSerialization JSONObjectWithData:appliedOutput options:0 error:&applyJSONError]
                        : nil;
                    if ([appliedResult[@"status"] intValue] == 0 && [applied[@"applied"] boolValue]) {
                        NSString *identifier = [applied[@"id"] isKindOfClass:[NSString class]] ? applied[@"id"] : @"unknown";
                        [self sendObject:@{
                            @"success": @YES,
                            @"message": [NSString stringWithFormat:@"File quarantined. Restore ID: %@", identifier],
                            @"clearFileScan": @(fileScan),
                        } function:@"receiveResponse"];
                        [self sendObject:@{@"phase": @"ready", @"message": @"Reviewed quarantine completed"}
                                function:@"receiveState"];
                        [self listQuarantine];
                        [self startScan];
                    } else {
                        NSString *detail = [self responseErrorFromResult:appliedResult
                                                                fallback:applyJSONError.localizedDescription ?: @"The reviewed quarantine was refused."];
                        [self sendObject:@{@"phase": @"error", @"message": detail}
                                function:@"receiveState"];
                    }
                });
            });
        });
    });
}

- (NSString *)responseErrorFromResult:(NSDictionary *)result fallback:(NSString *)fallback {
    NSString *message = [result[@"error"] isKindOfClass:[NSString class]] ? result[@"error"] : @"";
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *document = data.length
        ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil]
        : nil;
    NSString *detail = [document isKindOfClass:[NSDictionary class]] ? document[@"detail"] : nil;
    return [detail isKindOfClass:[NSString class]] && detail.length > 0
        ? detail
        : (message.length > 0 ? message : fallback);
}

- (BOOL)isValidSHA256:(NSString *)digest {
    if (![digest isKindOfClass:[NSString class]] || digest.length != 64) return NO;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
    return [digest rangeOfCharacterFromSet:allowed.invertedSet].location == NSNotFound;
}

- (BOOL)isValidCDHash:(NSString *)digest {
    if (![digest isKindOfClass:[NSString class]] || (digest.length != 40 && digest.length != 64)) return NO;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
    return [digest.lowercaseString rangeOfCharacterFromSet:allowed.invertedSet].location == NSNotFound;
}

- (BOOL)isValidEntryIdentifier:(NSString *)identifier {
    if (![identifier isKindOfClass:[NSString class]] || identifier.length != 32) return NO;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
    return [identifier rangeOfCharacterFromSet:allowed.invertedSet].location == NSNotFound;
}

- (void)listQuarantine {
    NSString *store = [[[self applicationDataDirectory] URLByAppendingPathComponent:@"quarantine"
                                                                          isDirectory:YES] path];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *result = [self runEngineArguments:@[
            @"response", @"list", @"--store", store, @"--pretty",
        ]];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSData *output = result[@"output"];
            NSDictionary *listing = output.length
                ? [NSJSONSerialization JSONObjectWithData:output options:0 error:nil]
                : nil;
            if ([result[@"status"] intValue] == 0 && [listing[@"entries"] isKindOfClass:[NSArray class]]) {
                [self sendObject:@{@"entries": listing[@"entries"]} function:@"receiveResponse"];
            } else {
                NSString *detail = [self responseErrorFromResult:result
                                                        fallback:@"The quarantine inventory could not be read."];
                [self sendObject:@{@"phase": @"error", @"message": detail} function:@"receiveState"];
            }
        });
    });
}

- (void)planRestoreIdentifier:(NSString *)identifier {
    if (self.scanning) return;
    if (![self isValidEntryIdentifier:identifier]) {
        [self sendObject:@{@"phase": @"error", @"message": @"The quarantine entry ID is invalid."}
                function:@"receiveState"];
        return;
    }
    NSString *store = [[[self applicationDataDirectory] URLByAppendingPathComponent:@"quarantine"
                                                                          isDirectory:YES] path];
    self.scanning = YES;
    [self sendObject:@{@"phase": @"scanning", @"message": @"Verifying quarantined file integrity…"}
            function:@"receiveState"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = [self runEngineArguments:@[
            @"response", @"restore", identifier, @"--store", store, @"--pretty",
        ]];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSData *output = result[@"output"];
            NSDictionary *plan = output.length
                ? [NSJSONSerialization JSONObjectWithData:output options:0 error:nil]
                : nil;
            NSString *target = [plan[@"target"] isKindOfClass:[NSString class]] ? plan[@"target"] : nil;
            NSString *digest = [plan[@"sha256"] isKindOfClass:[NSString class]] ? plan[@"sha256"] : nil;
            if ([result[@"status"] intValue] != 0 || !target.isAbsolutePath ||
                ![self isValidSHA256:digest]) {
                self.scanning = NO;
                NSString *detail = [self responseErrorFromResult:result
                                                        fallback:@"The restore plan could not be verified."];
                [self sendObject:@{@"phase": @"error", @"message": detail} function:@"receiveState"];
                return;
            }

            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"Restore this quarantined file?";
            alert.informativeText = [NSString stringWithFormat:
                @"RATtler verified the stored payload and will restore it only if the destination remains empty.\n\nPath: %@\nSHA-256: %@",
                target, digest];
            alert.alertStyle = NSAlertStyleWarning;
            [alert addButtonWithTitle:@"Restore File"];
            [alert addButtonWithTitle:@"Cancel"];
            if ([alert runModal] != NSAlertFirstButtonReturn) {
                self.scanning = NO;
                [self sendObject:@{@"phase": @"ready", @"message": @"Restore cancelled"}
                        function:@"receiveState"];
                return;
            }

            [self sendObject:@{@"phase": @"scanning", @"message": @"Applying reviewed restore…"}
                    function:@"receiveState"];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                NSDictionary *appliedResult = [self runEngineArguments:@[
                    @"response", @"restore", identifier, @"--store", store, @"--apply", @"--pretty",
                ]];
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.scanning = NO;
                    NSData *appliedOutput = appliedResult[@"output"];
                    NSDictionary *applied = appliedOutput.length
                        ? [NSJSONSerialization JSONObjectWithData:appliedOutput options:0 error:nil]
                        : nil;
                    if ([appliedResult[@"status"] intValue] == 0 && [applied[@"applied"] boolValue]) {
                        [self sendObject:@{@"success": @YES, @"message": @"File restored to its original path."}
                                function:@"receiveResponse"];
                        [self sendObject:@{@"phase": @"ready", @"message": @"Reviewed restore completed"}
                                function:@"receiveState"];
                        [self listQuarantine];
                        [self startScan];
                    } else {
                        NSString *detail = [self responseErrorFromResult:appliedResult
                                                                fallback:@"The reviewed restore was refused."];
                        [self sendObject:@{@"phase": @"error", @"message": detail}
                                function:@"receiveState"];
                    }
                });
            });
        });
    });
}

- (NSArray<NSString *> *)exceptionArgumentsForFinding:(NSDictionary *)exception apply:(BOOL)apply {
    NSString *ruleID = [exception[@"ruleId"] isKindOfClass:[NSString class]] ? exception[@"ruleId"] : nil;
    NSString *path = [exception[@"path"] isKindOfClass:[NSString class]] ? exception[@"path"] : nil;
    NSString *cdhash = [exception[@"cdhash"] isKindOfClass:[NSString class]] ? [exception[@"cdhash"] lowercaseString] : nil;
    NSString *sha256 = [exception[@"sha256"] isKindOfClass:[NSString class]] ? [exception[@"sha256"] lowercaseString] : nil;
    NSString *teamID = [exception[@"teamId"] isKindOfClass:[NSString class]] ? exception[@"teamId"] : nil;
    NSString *identifier = [exception[@"identifier"] isKindOfClass:[NSString class]] ? exception[@"identifier"] : nil;
    BOOL validRule = ruleID.length > 0 && ruleID.length <= 128;
    BOOL validPath = path.isAbsolutePath && path.length <= 4096;
    BOOL validHash = [self isValidCDHash:cdhash] || [self isValidSHA256:sha256];
    BOOL validSigner = teamID.length > 0 && teamID.length <= 128 && identifier.length > 0 && identifier.length <= 512;
    if (!validRule || !validPath || (!validHash && !validSigner)) return nil;
    NSURL *policy = [[self applicationDataDirectory] URLByAppendingPathComponent:@"exceptions.json"];
    NSMutableArray<NSString *> *arguments = [NSMutableArray arrayWithArray:@[
        @"exceptions", @"--policy", policy.path, @"--pretty", @"add",
        @"--rule-id", ruleID, @"--path", path,
        @"--reason", @"Reviewed in the RATtler app", @"--days", @"30",
    ]];
    if ([self isValidCDHash:cdhash]) [arguments addObjectsFromArray:@[@"--cdhash", cdhash]];
    if ([self isValidSHA256:sha256]) [arguments addObjectsFromArray:@[@"--sha256", sha256]];
    if (teamID.length > 0 && teamID.length <= 128) [arguments addObjectsFromArray:@[@"--team-id", teamID]];
    if (identifier.length > 0 && identifier.length <= 512) [arguments addObjectsFromArray:@[@"--identifier", identifier]];
    if (apply) [arguments addObject:@"--apply"];
    return arguments;
}

- (void)planFindingException:(NSDictionary *)exception fileScan:(BOOL)fileScan {
    if (self.scanning) return;
    NSArray<NSString *> *planArguments = [self exceptionArgumentsForFinding:exception apply:NO];
    if (planArguments == nil) {
        [self sendObject:@{ @"phase": @"error", @"message": @"This finding lacks a safe code or file identity for an exception." }
                function:@"receiveState"];
        return;
    }
    self.scanning = YES;
    [self sendObject:@{ @"phase": @"scanning", @"message": @"Validating a narrow reviewed exception…" }
            function:@"receiveState"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = [self runEngineArguments:planArguments];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSData *output = result[@"output"];
            NSDictionary *plan = output.length
                ? [NSJSONSerialization JSONObjectWithData:output options:0 error:nil] : nil;
            NSDictionary *entry = [plan[@"entry"] isKindOfClass:[NSDictionary class]] ? plan[@"entry"] : nil;
            NSDictionary *match = [entry[@"match"] isKindOfClass:[NSDictionary class]] ? entry[@"match"] : nil;
            NSString *path = [match[@"path"] isKindOfClass:[NSString class]] ? match[@"path"] : @"";
            NSString *ruleID = [entry[@"rule_id"] isKindOfClass:[NSString class]] ? entry[@"rule_id"] : @"";
            if ([result[@"status"] intValue] != 0 || !path.isAbsolutePath || ruleID.length == 0) {
                self.scanning = NO;
                NSString *detail = [self responseErrorFromResult:result fallback:@"The reviewed exception could not be validated."];
                [self sendObject:@{ @"phase": @"error", @"message": detail } function:@"receiveState"];
                return;
            }
            NSString *identity = match[@"cdhash"] ?: match[@"sha256"];
            if (![identity isKindOfClass:[NSString class]]) {
                identity = [NSString stringWithFormat:@"%@ / %@", match[@"team_id"] ?: @"", match[@"identifier"] ?: @""];
            }
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"Ignore this exact finding for 30 days?";
            alert.informativeText = [NSString stringWithFormat:
                @"The exception applies only to this rule, path, and cryptographic identity. Activity remains in the local timeline, and the exception expires automatically.\n\nRule: %@\nPath: %@\nIdentity: %@",
                ruleID, path, identity];
            alert.alertStyle = NSAlertStyleWarning;
            [alert addButtonWithTitle:@"Add Exception"];
            [alert addButtonWithTitle:@"Cancel"];
            if ([alert runModal] != NSAlertFirstButtonReturn) {
                self.scanning = NO;
                [self sendObject:@{ @"phase": @"ready", @"message": @"Exception cancelled" } function:@"receiveState"];
                return;
            }
            NSArray<NSString *> *applyArguments = [self exceptionArgumentsForFinding:exception apply:YES];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                NSDictionary *appliedResult = [self runEngineArguments:applyArguments];
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.scanning = NO;
                    NSData *appliedOutput = appliedResult[@"output"];
                    NSDictionary *applied = appliedOutput.length
                        ? [NSJSONSerialization JSONObjectWithData:appliedOutput options:0 error:nil] : nil;
                    if ([appliedResult[@"status"] intValue] == 0 && [applied[@"applied"] boolValue]) {
                        [self sendObject:@{ @"success": @YES, @"message": @"Reviewed exception added for 30 days." }
                                function:@"receiveResponse"];
                        [self listExceptions];
                        if (fileScan && self.lastFileScanPath.length > 0) {
                            [self startFileScanPath:self.lastFileScanPath];
                        } else {
                            [self startScan];
                        }
                    } else {
                        NSString *detail = [self responseErrorFromResult:appliedResult fallback:@"The exception was not added."];
                        [self sendObject:@{ @"phase": @"error", @"message": detail } function:@"receiveState"];
                    }
                });
            });
        });
    });
}

- (void)selectFileScan {
    if (self.scanning) return;
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.title = @"Choose a file or folder for Deep Scan";
    panel.prompt = @"Scan";
    panel.message = @"RATtler reads the selected contents locally. Nothing is uploaded.";
    panel.canChooseFiles = YES;
    panel.canChooseDirectories = YES;
    panel.allowsMultipleSelection = NO;
    panel.resolvesAliases = NO;
    if ([panel runModal] == NSModalResponseOK && panel.URL != nil) {
        [self startFileScanPath:panel.URL.path];
    }
}

- (void)startFileScanPath:(NSString *)path {
    if (self.scanning || !path.isAbsolutePath || path.length > 4096) return;
    NSURL *rules = [[NSBundle mainBundle] URLForResource:@"Rules" withExtension:nil];
    NSURL *exceptions = [[self applicationDataDirectory] URLByAppendingPathComponent:@"exceptions.json"];
    if (rules == nil) {
        [self sendObject:@{ @"phase": @"error", @"message": @"The bundled Deep Scan rules are missing." }
                function:@"receiveState"];
        return;
    }
    self.lastFileScanPath = [path copy];
    self.scanning = YES;
    [self sendObject:@{ @"phase": @"scanning", @"message": @"Deep Scan is inspecting the selected content locally…" }
            function:@"receiveState"];
    NSArray<NSString *> *arguments = @[
        @"files", @"scan", path, @"--rules", rules.path,
        @"--exceptions", exceptions.path, @"--pretty",
    ];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = [self runEngineArguments:arguments];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.scanning = NO;
            NSData *output = result[@"output"];
            NSDictionary *scan = output.length
                ? [NSJSONSerialization JSONObjectWithData:output options:0 error:nil] : nil;
            NSInteger status = [result[@"status"] integerValue];
            if ((status == 0 || status == 1 || status == 3) && [scan isKindOfClass:[NSDictionary class]]) {
                [self sendData:output function:@"receiveFileScan"];
                [self sendObject:@{ @"phase": @"ready", @"message": @"Deep Scan completed" }
                        function:@"receiveState"];
            } else {
                NSString *detail = [self responseErrorFromResult:result fallback:@"Deep Scan could not inspect that target."];
                [self sendObject:@{ @"phase": @"error", @"message": detail } function:@"receiveState"];
            }
        });
    });
}

- (void)listExceptions {
    NSURL *policy = [[self applicationDataDirectory] URLByAppendingPathComponent:@"exceptions.json"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *result = [self runEngineArguments:@[
            @"exceptions", @"--policy", policy.path, @"--pretty", @"list", @"--include-expired",
        ]];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSData *output = result[@"output"];
            NSDictionary *listing = output.length
                ? [NSJSONSerialization JSONObjectWithData:output options:0 error:nil] : nil;
            if ([result[@"status"] intValue] == 0 && [listing[@"entries"] isKindOfClass:[NSArray class]]) {
                [self sendObject:@{ @"exceptions": listing[@"entries"] } function:@"receiveResponse"];
            }
        });
    });
}

- (void)planRemoveException:(NSString *)identifier {
    if (self.scanning || ![self isValidEntryIdentifier:identifier]) return;
    NSURL *policy = [[self applicationDataDirectory] URLByAppendingPathComponent:@"exceptions.json"];
    NSDictionary *result = [self runEngineArguments:@[
        @"exceptions", @"--policy", policy.path, @"--pretty", @"remove", identifier,
    ]];
    NSData *output = result[@"output"];
    NSDictionary *plan = output.length ? [NSJSONSerialization JSONObjectWithData:output options:0 error:nil] : nil;
    NSDictionary *entry = [plan[@"entry"] isKindOfClass:[NSDictionary class]] ? plan[@"entry"] : nil;
    if ([result[@"status"] intValue] != 0 || entry == nil) return;
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Remove this reviewed exception?";
    alert.informativeText = [NSString stringWithFormat:@"Rule %@ will be evaluated normally on the next scan. No file or activity history will be deleted.", entry[@"rule_id"] ?: @"unknown"];
    [alert addButtonWithTitle:@"Remove Exception"];
    [alert addButtonWithTitle:@"Cancel"];
    if ([alert runModal] != NSAlertFirstButtonReturn) return;
    NSDictionary *appliedResult = [self runEngineArguments:@[
        @"exceptions", @"--policy", policy.path, @"--pretty", @"remove", identifier, @"--apply",
    ]];
    NSData *appliedOutput = appliedResult[@"output"];
    NSDictionary *applied = appliedOutput.length
        ? [NSJSONSerialization JSONObjectWithData:appliedOutput options:0 error:nil] : nil;
    if ([appliedResult[@"status"] intValue] == 0 && [applied[@"applied"] boolValue]) {
        [self sendObject:@{ @"success": @YES, @"message": @"Reviewed exception removed." } function:@"receiveResponse"];
        [self listExceptions];
        [self startScan];
    }
}

- (void)enableRecovery {
    if (self.scanning || [self recoveryEnabled]) return;
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Enable the Recovery Vault?";
    alert.informativeText = @"RATtler will keep up to 512 MB of versioned document and photo copies in private local storage. Nothing is uploaded. The first backup may take several minutes.";
    alert.alertStyle = NSAlertStyleInformational;
    [alert addButtonWithTitle:@"Enable Recovery Vault"];
    [alert addButtonWithTitle:@"Cancel"];
    if ([alert runModal] != NSAlertFirstButtonReturn) return;

    self.scanning = YES;
    [self sendObject:@{@"phase": @"scanning", @"message": @"Creating protected recovery copies…"}
            function:@"receiveState"];
    NSArray<NSString *> *arguments = [self recoveryBackupArguments];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = [self runEngineArguments:arguments];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.scanning = NO;
            NSData *output = result[@"output"];
            NSDictionary *document = output.length
                ? [NSJSONSerialization JSONObjectWithData:output options:0 error:nil]
                : nil;
            if ([result[@"status"] intValue] == 0 && [document[@"applied"] boolValue]) {
                [[NSFileManager defaultManager] removeItemAtURL:[self recoveryErrorURL] error:nil];
                NSInteger count = [document[@"stored_files"] integerValue];
                [self sendObject:@{
                    @"success": @YES,
                    @"message": [NSString stringWithFormat:@"Recovery Vault enabled with %ld protected files.", (long)count],
                } function:@"receiveResponse"];
                [self sendCapabilities];
                [self startScan];
            } else {
                NSString *detail = [document[@"error"] isKindOfClass:[NSString class]] ? document[@"error"] : @"The Recovery Vault could not be enabled.";
                [self sendObject:@{@"phase": @"error", @"message": detail} function:@"receiveState"];
            }
        });
    });
}

- (void)recoverFiles {
    if (self.scanning || ![self recoveryEnabled]) return;
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd-HHmmss";
    NSString *folder = [NSString stringWithFormat:@"RATtler Recovered %@", [formatter stringFromDate:[NSDate date]]];
    NSURL *destination = [NSURL fileURLWithPath:[NSHomeDirectory() stringByAppendingPathComponent:@"Desktop"]
                                     isDirectory:YES];
    destination = [destination URLByAppendingPathComponent:folder isDirectory:YES];
    NSURL *store = [[self applicationDataDirectory] URLByAppendingPathComponent:@"recovery" isDirectory:YES];
    NSArray<NSString *> *planArguments = @[
        @"recovery", @"restore-all", @"--store", store.path,
        @"--destination", destination.path, @"--pretty",
    ];
    self.scanning = YES;
    [self sendObject:@{@"phase": @"scanning", @"message": @"Verifying protected recovery copies…"}
            function:@"receiveState"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = [self runEngineArguments:planArguments];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSData *output = result[@"output"];
            NSDictionary *plan = output.length
                ? [NSJSONSerialization JSONObjectWithData:output options:0 error:nil]
                : nil;
            NSInteger count = [plan[@"planned_files"] integerValue];
            if ([result[@"status"] intValue] != 0 || count <= 0) {
                self.scanning = NO;
                NSString *detail = [plan[@"error"] isKindOfClass:[NSString class]] ? plan[@"error"] : @"No verified recovery copies are available.";
                [self sendObject:@{@"phase": @"error", @"message": detail} function:@"receiveState"];
                return;
            }
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"Recover protected copies?";
            alert.informativeText = [NSString stringWithFormat:@"RATtler verified %ld recoverable files. It will copy the previous protected versions into a new Desktop folder and will not overwrite any original file.\n\nDestination: %@", (long)count, destination.path];
            alert.alertStyle = NSAlertStyleWarning;
            [alert addButtonWithTitle:@"Recover Copies"];
            [alert addButtonWithTitle:@"Cancel"];
            if ([alert runModal] != NSAlertFirstButtonReturn) {
                self.scanning = NO;
                [self sendObject:@{@"phase": @"ready", @"message": @"Recovery cancelled"}
                        function:@"receiveState"];
                return;
            }
            [self sendObject:@{@"phase": @"scanning", @"message": @"Recovering verified copies…"}
                    function:@"receiveState"];
            NSArray<NSString *> *applyArguments = @[
                @"recovery", @"restore-all", @"--store", store.path,
                @"--destination", destination.path, @"--apply", @"--pretty",
            ];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                NSDictionary *appliedResult = [self runEngineArguments:applyArguments];
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.scanning = NO;
                    NSData *appliedOutput = appliedResult[@"output"];
                    NSDictionary *applied = appliedOutput.length
                        ? [NSJSONSerialization JSONObjectWithData:appliedOutput options:0 error:nil]
                        : nil;
                    if ([appliedResult[@"status"] intValue] == 0 && [applied[@"applied"] boolValue]) {
                        NSInteger restored = [applied[@"restored_files"] integerValue];
                        [self sendObject:@{
                            @"success": @YES,
                            @"message": [NSString stringWithFormat:@"Recovered %ld files into a new Desktop folder.", (long)restored],
                        } function:@"receiveResponse"];
                        [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[destination]];
                        [self sendObject:@{@"phase": @"ready", @"message": @"Recovery copies created"}
                                function:@"receiveState"];
                    } else {
                        NSString *detail = [applied[@"error"] isKindOfClass:[NSString class]] ? applied[@"error"] : @"Recovery was refused because verification changed.";
                        [self sendObject:@{@"phase": @"error", @"message": detail} function:@"receiveState"];
                    }
                });
            });
        });
    });
}

- (void)resumeRecovery {
    if (self.scanning || ![self recoveryFrozen]) return;
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Resume automatic recovery backups?";
    alert.informativeText = @"Only resume after investigating the ransomware finding and confirming that destructive activity has stopped. Existing recovery versions will remain in the vault.";
    alert.alertStyle = NSAlertStyleWarning;
    [alert addButtonWithTitle:@"Resume Backups"];
    [alert addButtonWithTitle:@"Cancel"];
    if ([alert runModal] != NSAlertFirstButtonReturn) return;
    NSError *error = nil;
    if (![[NSFileManager defaultManager] removeItemAtURL:[self recoveryFreezeURL] error:&error]) {
        [self sendObject:@{@"phase": @"error", @"message": error.localizedDescription ?: @"Could not resume backups."}
                function:@"receiveState"];
        return;
    }
    [self sendCapabilities];
    [self sendObject:@{@"success": @YES, @"message": @"Automatic recovery backups resumed."}
            function:@"receiveResponse"];
    [self startScan];
}

- (NSDictionary *)runEngineArguments:(NSArray<NSString *> *)arguments {
    NSURL *engine = [[NSBundle mainBundle] URLForResource:@"rattler-engine"
                                            withExtension:nil
                                             subdirectory:@"Engine"];
    if (engine == nil || ![[NSFileManager defaultManager] isExecutableFileAtPath:engine.path]) {
        return @{@"output": [NSData data], @"error": @"The RATtler detection engine is missing from this app build.", @"status": @127};
    }

    char outputTemplate[] = "/tmp/rattler-ui-output-XXXXXX";
    char errorTemplate[] = "/tmp/rattler-ui-error-XXXXXX";
    int outputDescriptor = mkstemp(outputTemplate);
    int errorDescriptor = mkstemp(errorTemplate);
    if (outputDescriptor < 0 || errorDescriptor < 0) {
        if (outputDescriptor >= 0) {
            close(outputDescriptor);
            unlink(outputTemplate);
        }
        if (errorDescriptor >= 0) {
            close(errorDescriptor);
            unlink(errorTemplate);
        }
        return @{@"output": [NSData data], @"error": @"RATtler could not create private engine output.", @"status": @126};
    }
    unlink(outputTemplate);
    unlink(errorTemplate);
    NSFileHandle *output = [[NSFileHandle alloc] initWithFileDescriptor:outputDescriptor closeOnDealloc:YES];
    NSFileHandle *error = [[NSFileHandle alloc] initWithFileDescriptor:errorDescriptor closeOnDealloc:YES];

    NSTask *task = [[NSTask alloc] init];
    task.executableURL = engine;
    task.arguments = arguments;
    task.standardInput = [NSFileHandle fileHandleWithNullDevice];
    task.standardOutput = output;
    task.standardError = error;
    NSError *launchError = nil;
    if (![task launchAndReturnError:&launchError]) {
        return @{@"output": [NSData data], @"error": launchError.localizedDescription ?: @"Engine launch failed", @"status": @126};
    }
    [task waitUntilExit];
    [output synchronizeFile];
    [error synchronizeFile];
    [output seekToFileOffset:0];
    [error seekToFileOffset:0];
    NSData *outputData = [output readDataToEndOfFile];
    NSData *errorData = [error readDataToEndOfFile];
    NSString *errorText = [[NSString alloc] initWithData:errorData encoding:NSUTF8StringEncoding] ?: @"";
    return @{@"output": outputData, @"error": [errorText stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet], @"status": @(task.terminationStatus)};
}

- (void)exportReport {
    if (self.lastReport.length == 0) return;
    NSSavePanel *panel = [NSSavePanel savePanel];
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd-HHmm";
    panel.nameFieldStringValue = [NSString stringWithFormat:@"RATtler-report-%@.json", [formatter stringFromDate:[NSDate date]]];
    panel.allowedContentTypes = @[UTTypeJSON];
    if ([panel runModal] != NSModalResponseOK || panel.URL == nil) return;
    NSError *error = nil;
    if (![self.lastReport writeToURL:panel.URL options:NSDataWritingAtomic error:&error]) {
        [self sendObject:@{@"phase": @"error", @"message": error.localizedDescription ?: @"The report could not be exported."}
                function:@"receiveState"];
    } else {
        [self sendObject:@{@"phase": @"ready", @"message": @"Report exported"}
                function:@"receiveState"];
    }
}

- (void)sendCapabilities {
    NSURL *directory = [self applicationDataDirectory];
    BOOL baseline = [[NSFileManager defaultManager] fileExistsAtPath:[[directory URLByAppendingPathComponent:@"baseline.json"] path]];
    BOOL nativeEvents = [[NSFileManager defaultManager] fileExistsAtPath:[[directory URLByAppendingPathComponent:@"native-events.jsonl"] path]];
    BOOL yaraRules = [[NSFileManager defaultManager] fileExistsAtPath:[[[NSBundle mainBundle] URLForResource:@"Rules" withExtension:nil] path]];
    NSString *appPath = [NSBundle mainBundle].bundleURL.path.stringByStandardizingPath;
    BOOL installed = [appPath isEqualToString:@"/Applications/RATtler.app"] ||
        [appPath hasPrefix:@"/Applications/"];
    [self sendObject:@{
        @"baseline": @(baseline),
        @"nativeEvents": @(nativeEvents),
        @"yaraRules": @(yaraRules),
        @"recovery": @([self recoveryEnabled]),
        @"recoveryFrozen": @([self recoveryFrozen]),
        @"recoveryError": @([[NSFileManager defaultManager] fileExistsAtPath:[self recoveryErrorURL].path]),
        @"installed": @(installed),
        @"appPath": appPath ?: @"",
        @"version": @"0.13.2",
    }
            function:@"receiveCapabilities"];
}

- (void)sendObject:(NSDictionary *)object function:(NSString *)function {
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:0 error:nil];
    [self sendData:data function:function];
}

- (void)sendData:(NSData *)data function:(NSString *)function {
    NSString *base64 = [data base64EncodedStringWithOptions:0];
    NSString *script = [NSString stringWithFormat:@"window.RATtler.%@('%@')", function, base64];
    [self.webView evaluateJavaScript:script completionHandler:^(id value, NSError *error) {
        (void)value;
        if (error != nil) NSLog(@"RATtler interface error: %@", error.localizedDescription);
    }];
}

- (void)showNativeError:(NSString *)message {
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"RATtler could not start";
    alert.informativeText = message;
    alert.alertStyle = NSAlertStyleCritical;
    [alert runModal];
}

@end

static RATAppDelegate *g_appDelegate;

int main(int argc, const char *argv[]) {
    (void)argc;
    (void)argv;
    @autoreleasepool {
        NSApplication *application = [NSApplication sharedApplication];
        g_appDelegate = [[RATAppDelegate alloc] init];
        application.delegate = g_appDelegate;
        application.activationPolicy = NSApplicationActivationPolicyRegular;
        [application run];
    }
    return 0;
}
