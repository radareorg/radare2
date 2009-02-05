/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_util.h"

int rax(const char *str)
{
	u64 n = r_num_math(NULL, str);
	switch(*str) {
	case 'q':
		return 0;
	}
	if (str[0]=='0'&&str[1]=='x')
		printf("%lld\n", n);
	else printf("0x%llx\n", n);
	return 1;
}

int main(int argc, char **argv)
{
	int i;
	char buf[1024];

	if (argc == 1) {
		while(!feof(stdin)) {
			fgets(buf, 1023, stdin);
			if (feof(stdin)) break;
			buf[strlen(buf)-1] = '\0';
			if (!rax(buf)) break;
		}
		return 0;
	}

	if (!strcmp(argv[1], "-h"))
		printf("Usage: rax [-] | [-s] [-e] [int|0x|Fx|.f|.o] [...]\n");

	for(i=1; i<argc; i++)
		rax( argv[i] );

	return 0;

}
