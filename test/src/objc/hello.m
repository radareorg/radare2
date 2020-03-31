#import <Foundation/Foundation.h>
#include "employee.h"

int main(int argc, const char * argv[]){
	@autoreleasepool{
		NSLog(@"Hello World Objective-C");
		Employee *ins = [[Employee alloc] init];
		[ins sayHello];
		[Employee sayHello];

		printf ("base %p\n", ins);
		void *base = ins;
		printf ("iii %p _username\n", [ins p0] - base);
		printf ("iii %p _firstName\n", [ins p1] - base);
		printf ("iii %p _shortWord\n", [ins p2] - base);
		printf ("iii %p _wideWord\n", [ins p3] - base);
		unsigned char *p = (void*)ins;
int i;
		for (i = 0; i< 32; i++) {
			printf ("%02x ", p[i]);
		}
printf ("\n");
		
		NSString *s = @"HELLO NSSTRING";
		printf ("%p\n", s);
	asm("int3");

	}
	return 0;
}
