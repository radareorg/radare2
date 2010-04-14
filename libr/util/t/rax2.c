/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include <r_util.h>

static int rax(const char *str) {
	ut64 n;
	if (*str=='q')
		return 0;
 	n = r_num_math(NULL, str);
	if (str[0]=='0'&&str[1]=='x')
		printf("%"PFMT64d"\n", n);
	else printf("0x%"PFMT64x"\n", n);
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
	if (argv[1][0]=='-') {
		switch(argv[1][1]) {
		case 'h':
			printf("Usage: rax2 [-hV] [expression]\n");
			return 0;
		case 'V':
			printf("rax2 v"VERSION"\n");
			return 0;
		}
	}
	for(i=1; i<argc; i++)
		rax( argv[i] );
	return 0;
}
