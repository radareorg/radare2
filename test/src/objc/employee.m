#include "employee.h"

@implementation Employee
	-(void)helloWorld{
		NSLog(@"Hello World");
	}
	- sayHello {
		NSLog(@"Hello Instance");
	}
	- (void*)p0 { return &_username; }
	- (void*)p1 { return &_firstName; }
	- (void*)p2 { return &_shortWord; }
	- (void*)p3 { return &_wideWord; }
	- (void*)base { return self; }
	+ sayHello {
		NSLog(@"Hello Class");
	}
@end
