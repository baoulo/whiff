// Boat view (Objective-C++)
#import <UIKit/UIKit.h>
#include <vector>
@import Foundation;

@interface BoatView : UIView
@property (nonatomic, copy) NSString *name;
@end

@implementation BoatView
- (void)layoutSubviews { [super layoutSubviews]; }
@end
