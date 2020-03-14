/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include <r_util.h>

static int help(bool verbose) {
	printf ("Usage: r2r [test]\n");
	if (verbose) {
		printf (" TODO: verbose help\n");
	}
	return 1;
}

int main(int argc, char **argv) {
	int c;
	while ((c = r_getopt (argc, argv, "h")) != -1) {
		switch (c) {
		case 'h':
			return help (true);
		default:
			return help (false);
		}
	}

	int i;
	for (i = optind; i < argc; i++) {
		printf ("%s\n", argv[i]);
	}
	return 0;
}
