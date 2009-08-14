#include "r_asm.h"

int main(int argc, char **argv)
{
	struct r_asm_t *a;
	char *arg;
	int num, i = 0;
	if (argc<2) {
		printf("Usage: fastcall [nargs]\n");
		return 1;
	}
	num = atoi(argv[1]);
	a = r_asm_new();

	printf("Supported plugins:\n");
	r_asm_list(a);
	r_asm_set(a, "asm_x86_nasm");

	printf("Fastcall args for %d\n", atoi(argv[1]));

	printf("Using plugin: %s\n", a->cur->name);
	do {
		arg = r_asm_fastcall(a, i++, num);
		if (arg)
			printf("%s\n", arg);
	} while(arg);
	return 0;
}
