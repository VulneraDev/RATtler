#import <AppKit/AppKit.h>
#import <WebKit/WebKit.h>

@interface RATSnapshotter : NSObject <WKNavigationDelegate>
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) WKWebView *webView;
@property(nonatomic, strong) NSData *reportData;
@property(nonatomic, strong) NSURL *outputURL;
@property(nonatomic, copy) NSString *viewID;
- (instancetype)initWithPage:(NSURL *)page report:(NSData *)report output:(NSURL *)output view:(NSString *)view;
- (void)start;
@end

@implementation RATSnapshotter

- (instancetype)initWithPage:(NSURL *)page report:(NSData *)report output:(NSURL *)output view:(NSString *)view {
    self = [super init];
    if (self) {
        _reportData = report;
        _outputURL = output;
        _viewID = [view copy];

        WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = NO;
        _webView = [[WKWebView alloc] initWithFrame:NSMakeRect(0, 0, 1180, 760)
                                      configuration:configuration];
        _webView.navigationDelegate = self;

        _window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 1180, 760)
                                             styleMask:NSWindowStyleMaskBorderless
                                               backing:NSBackingStoreBuffered
                                                 defer:NO];
        _window.contentView = _webView;
        _window.alphaValue = 0.01;
        [_window orderBack:nil];

        NSURL *directory = [page URLByDeletingLastPathComponent];
        [_webView loadFileURL:page allowingReadAccessToURL:directory];
    }
    return self;
}

- (void)start {
    [NSApp run];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    (void)webView;
    (void)navigation;
    NSData *capabilities = [NSJSONSerialization dataWithJSONObject:@{
        @"baseline": @YES,
        @"nativeEvents": @YES,
        @"installed": @YES,
        @"version": @"0.9.0",
    } options:0 error:nil];
    NSData *ready = [NSJSONSerialization dataWithJSONObject:@{
        @"phase": @"ready",
        @"message": @"Scan completed",
    } options:0 error:nil];
    NSString *script = [NSString stringWithFormat:
        @"document.documentElement.classList.add('snapshot');"
         "window.RATtler.receiveCapabilities('%@');"
         "window.RATtler.receiveReport('%@');"
         "window.RATtler.receiveState('%@');"
         "document.querySelector('[data-view=\"%@\"]')?.click();",
        [capabilities base64EncodedStringWithOptions:0],
        [self.reportData base64EncodedStringWithOptions:0],
        [ready base64EncodedStringWithOptions:0],
        self.viewID];
    [self.webView evaluateJavaScript:script completionHandler:^(id value, NSError *error) {
        (void)value;
        if (error != nil) {
            [self finishWithError:error.localizedDescription];
            return;
        }
        NSString *contentSelector = @"#dashboard-content";
        if ([self.viewID isEqualToString:@"bluepulse"]) contentSelector = @"#bluepulse-content";
        if ([self.viewID isEqualToString:@"ransomware"]) contentSelector = @"#ransomware-content";
        NSString *diagnostic = [NSString stringWithFormat:
            @"JSON.stringify({children:document.querySelector('%@').childElementCount,toast:document.querySelector('#toast p').textContent,opacity:getComputedStyle(document.querySelector('#%@')).opacity})",
            contentSelector, self.viewID];
        [self.webView evaluateJavaScript:diagnostic completionHandler:^(id result, NSError *diagnosticError) {
            if (diagnosticError != nil || ![result isKindOfClass:[NSString class]]) {
                [self finishWithError:diagnosticError.localizedDescription ?: @"Could not validate the rendered interface"];
                return;
            }
            NSData *data = [(NSString *)result dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *state = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if ([state[@"children"] integerValue] == 0 || [state[@"opacity"] doubleValue] == 0) {
                NSString *toast = [state[@"toast"] isKindOfClass:[NSString class]] ? state[@"toast"] : @"";
                [self finishWithError:[NSString stringWithFormat:@"Interface did not render. %@", toast]];
                return;
            }
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [self capture];
            });
        }];
    }];
}

- (void)capture {
    WKSnapshotConfiguration *configuration = [[WKSnapshotConfiguration alloc] init];
    configuration.rect = NSMakeRect(0, 0, 1180, 760);
    configuration.snapshotWidth = @1180;
    [self.webView takeSnapshotWithConfiguration:configuration
                              completionHandler:^(NSImage *image, NSError *error) {
        if (error != nil || image == nil) {
            [self finishWithError:error.localizedDescription ?: @"WebKit returned no image"];
            return;
        }
        NSData *tiff = image.TIFFRepresentation;
        NSBitmapImageRep *bitmap = [NSBitmapImageRep imageRepWithData:tiff];
        NSData *png = [bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        NSError *writeError = nil;
        if (png == nil || ![png writeToURL:self.outputURL options:NSDataWritingAtomic error:&writeError]) {
            [self finishWithError:writeError.localizedDescription ?: @"Could not encode screenshot"];
            return;
        }
        exit(0);
    }];
}

- (void)finishWithError:(NSString *)message {
    fprintf(stderr, "screenshot failed: %s\n", message.UTF8String);
    exit(1);
}

@end

static RATSnapshotter *g_snapshotter;

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 4 && argc != 5) {
            fprintf(stderr, "usage: render-screenshot PAGE REPORT OUTPUT [dashboard|bluepulse|ransomware]\n");
            return 2;
        }
        NSURL *page = [NSURL fileURLWithPath:@(argv[1])];
        NSData *report = [NSData dataWithContentsOfFile:@(argv[2])];
        NSURL *output = [NSURL fileURLWithPath:@(argv[3])];
        NSString *view = argc == 5 ? @(argv[4]) : @"dashboard";
        if (![@[@"dashboard", @"bluepulse", @"ransomware"] containsObject:view]) {
            fprintf(stderr, "unsupported screenshot view\n");
            return 2;
        }
        if (report == nil) {
            fprintf(stderr, "could not read report fixture\n");
            return 2;
        }
        [NSApplication sharedApplication];
        NSApp.activationPolicy = NSApplicationActivationPolicyProhibited;
        g_snapshotter = [[RATSnapshotter alloc] initWithPage:page report:report output:output view:view];
        [g_snapshotter start];
        return 0;
    }
}
