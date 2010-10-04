#undef __UNIX__
#undef __WINDOWS__
#if __WIN32__ || __CYGWIN__ || MINGW32
#define __WINDOWS__ 1
#else
#define __UNIX__ 1
#endif

#include <stdio.h>

struct shellcode_t {
	char *name;
	char *desc;
	unsigned char *data;
	int len;
	/* flagz */
	int cmd;
	int host;
	int port;
};

extern struct shellcode_t shellcodes[];
void process_syscall();
int test();
