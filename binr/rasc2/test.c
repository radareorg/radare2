#include <stdio.h>
#include <stdlib.h>

int swallow_redpill () {
	unsigned char m[2+4], rpill[] = "\x0f\x01\x0d\x00\x00\x00\x00\xc3";
	*((unsigned*)&rpill[3]) = (unsigned long int) m;
	((void(*)())&rpill)();
	return (m[5]>0xd0) ? 1 : 0;
}

int test () {
	printf("Testing architecture: %s (TODO)\n", "x86");
	system("/sbin/sysctl kernel.randomize_va_space");
	system("/sbin/sysctl vm.vdso_enabled");
	printf("Executable stack: %s (TODO)\n", "true");
	printf("W^X flag: %s (TODO)\n", "true");
	printf("Red pill: %d\n", swallow_redpill());
	printf("Generate cores: %s (TODO)\n", "true");
	return 0;
}
