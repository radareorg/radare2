/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

#include <r_bininfo.h>

int main(int argc, char **argv)
{
	char file[1024];
	int line = 0;
	struct r_bininfo_t *bi;

	if (argc <3) {
		eprintf("Usage: rabini [file] [addr]\n");
		return 1;
	}

	bi = r_bininfo_new();
	if (!r_bininfo_open(bi, argv[1], R_FALSE, "bininfo_addr2line")) {
		eprintf("Cannot open file\n");
		return 1;
	}
	printf("List of plugins:\n");
	r_bininfo_list(bi);
	printf("--\n");
	file[0]='\0';
	r_bininfo_get_line(bi, r_num_get(NULL, argv[2]), file, 1023, &line);
	printf("FILE: %s\n", file);
	printf("LINE: %d\n", line);
	r_bininfo_free(bi);

	return 0;
}
