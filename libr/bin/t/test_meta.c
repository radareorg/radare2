/* radare - LGPL - Copyright 2010 nibble <.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>

int main(int argc, char **argv)
{
	char file[1024];
	int line = 0;
	RBin *bin;

	if (argc <3) {
		eprintf("Usage: %s [file] [addr]\n", argv[0]);
		return 1;
	}

	bin = r_bin_new ();
	if (!r_bin_load (bin, argv[1], NULL)) {
		eprintf ("r_bin: Cannot open '%s'\n", argv[1]);
		return 1;
	}
	file[0]='\0';
	if (!r_bin_meta_get_line (bin, r_num_get(NULL, argv[2]), file, 1023, &line)) {
		eprintf ("Cannot get metadata\n");
		return 1;
	}
	printf("FILE: %s\n", file);
	printf("LINE: %d\n", line);
	r_bin_free(bin);

	return 0;
}
