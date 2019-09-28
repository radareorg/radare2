/* radare - LGPL - Copyright 2012-2019 - pancake */

#include <r_main.h>

int main(int argc, char **argv) {
	int rc = 1;
	RMain *m = r_main_new (argv[0]);
	if (m) {
		rc = r_main_run (m, argc, argv);
		r_main_free (m);
	}
	return rc;
}
