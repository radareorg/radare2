#import <Foundation/Foundation.h>
@interface Employee : NSObject
	//property declaration
	@property (retain) NSString* username;
	@property (retain) NSString *firstName;
	@property (readonly) short shortWord;
	@property (readonly) uint64_t wideWord;
	// @private NSString *lastName;
	// @private (retain, nonatomic) NSString* name;

	// methods
	+ sayHello;
//	+ (void)loadTableData:(int);
	//method declaration
	- (void) helloWorld;
	- (void*)p0;
	- (void*)p1;
	- (void*)p2;
	- (void*)p3;
@end
