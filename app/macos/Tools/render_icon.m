#import <AppKit/AppKit.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 2;
        NSImage *image = [[NSImage alloc] initWithSize:NSMakeSize(1024, 1024)];
        [image lockFocus];

        NSRect tileRect = NSMakeRect(52, 52, 920, 920);
        NSBezierPath *tile = [NSBezierPath bezierPathWithRoundedRect:tileRect xRadius:218 yRadius:218];
        NSGradient *background = [[NSGradient alloc] initWithStartingColor:[NSColor colorWithRed:0.04 green:0.075 blue:0.105 alpha:1]
                                                               endingColor:[NSColor colorWithRed:0.012 green:0.025 blue:0.042 alpha:1]];
        [background drawInBezierPath:tile angle:-48];

        NSBezierPath *badge = [NSBezierPath bezierPathWithRoundedRect:NSMakeRect(212, 212, 600, 600) xRadius:170 yRadius:170];
        NSGradient *badgeGradient = [[NSGradient alloc] initWithStartingColor:[NSColor colorWithRed:0.36 green:0.94 blue:0.64 alpha:1]
                                                                    endingColor:[NSColor colorWithRed:0.08 green:0.56 blue:0.40 alpha:1]];
        [badgeGradient drawInBezierPath:badge angle:-52];

        NSBezierPath *shield = [NSBezierPath bezierPath];
        [shield moveToPoint:NSMakePoint(512, 698)];
        [shield curveToPoint:NSMakePoint(680, 638) controlPoint1:NSMakePoint(566, 683) controlPoint2:NSMakePoint(625, 665)];
        [shield lineToPoint:NSMakePoint(664, 484)];
        [shield curveToPoint:NSMakePoint(512, 332) controlPoint1:NSMakePoint(653, 407) controlPoint2:NSMakePoint(592, 352)];
        [shield curveToPoint:NSMakePoint(360, 484) controlPoint1:NSMakePoint(432, 352) controlPoint2:NSMakePoint(371, 407)];
        [shield lineToPoint:NSMakePoint(344, 638)];
        [shield curveToPoint:NSMakePoint(512, 698) controlPoint1:NSMakePoint(399, 665) controlPoint2:NSMakePoint(458, 683)];
        [shield closePath];
        [[NSColor colorWithWhite:0.035 alpha:0.88] setFill];
        [shield fill];

        NSDictionary *attributes = @{
            NSFontAttributeName: [NSFont systemFontOfSize:230 weight:NSFontWeightHeavy],
            NSForegroundColorAttributeName: [NSColor colorWithRed:0.29 green:0.88 blue:0.59 alpha:1]
        };
        NSAttributedString *letter = [[NSAttributedString alloc] initWithString:@"R" attributes:attributes];
        NSSize letterSize = letter.size;
        [letter drawAtPoint:NSMakePoint(512 - letterSize.width / 2, 485 - letterSize.height / 2)];

        NSBezierPath *dot = [NSBezierPath bezierPathWithOvalInRect:NSMakeRect(745, 738, 82, 82)];
        [[NSColor colorWithRed:0.98 green:0.72 blue:0.26 alpha:1] setFill];
        [dot fill];

        [image unlockFocus];
        NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc] initWithData:image.TIFFRepresentation];
        NSData *png = [bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        return [png writeToFile:[NSString stringWithUTF8String:argv[1]] atomically:YES] ? 0 : 1;
    }
}
